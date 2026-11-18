from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import Administrator, AuditEvent
from backend.services import auth

ADMIN = {"username": "admin", "password": "password123"}


def test_setup_creates_admin_and_logs_in(api):
    response = api.post("/api/auth/setup", json=ADMIN)
    assert response.status_code == 201
    assert response.json()["username"] == "admin"
    assert "password_hash" not in response.json()

    response = api.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "admin"


def test_setup_only_once(admin_api):
    response = admin_api.post("/api/auth/setup", json={"username": "other", "password": "password456"})
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "an administrator already exists"


def test_setup_validates_input(api):
    response = api.post("/api/auth/setup", json={"username": "a b", "password": "short"})
    assert response.status_code == 422
    fields = [field["field"] for field in response.json()["error"]["fields"]]
    assert fields == ["username", "password"]


def test_cookie_is_http_only(api):
    response = api.post("/api/auth/setup", json=ADMIN)
    cookie = response.headers["set-cookie"].lower()
    assert "inds_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_login_and_logout(admin_api, database):
    engine, _, _ = database
    admin_api.post("/api/auth/logout")
    assert admin_api.get("/api/auth/me").status_code == 401

    response = admin_api.post("/api/auth/login", json={"username": "ADMIN", "password": "password123"})
    assert response.status_code == 200
    assert response.json()["last_login_at"] is not None
    assert admin_api.get("/api/auth/me").status_code == 200

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "admin.login"))
        assert event.outcome == "success"
        assert event.actor_type == "administrator"


def test_wrong_password(admin_api, database):
    engine, _, _ = database
    admin_api.post("/api/auth/logout")

    response = admin_api.post("/api/auth/login", json={"username": "admin", "password": "wrongpass1"})
    assert response.status_code == 401
    assert response.json() == {"error": {"status": 401, "message": "wrong username or password"}}

    response = admin_api.post("/api/auth/login", json={"username": "nobody", "password": "password123"})
    assert response.status_code == 401

    with Session(engine) as session:
        events = session.scalars(select(AuditEvent).where(AuditEvent.outcome == "failure")).all()
        assert [event.details_json["username"] for event in events] == ["admin", "nobody"]


def test_account_locked_after_five_failures(admin_api):
    admin_api.post("/api/auth/logout")
    for _ in range(auth.MAX_FAILED_LOGINS):
        admin_api.post("/api/auth/login", json={"username": "admin", "password": "wrongpass1"})

    response = admin_api.post("/api/auth/login", json=ADMIN)
    assert response.status_code == 429


def test_disabled_admin_is_logged_out(admin_api, database):
    engine, _, _ = database
    with Session(engine) as session:
        admin = session.scalar(select(Administrator))
        admin.is_active = False
        session.commit()

    assert admin_api.get("/api/auth/me").status_code == 401
    assert admin_api.post("/api/auth/login", json=ADMIN).status_code == 401


def test_invalid_cookie(api):
    api.cookies.set("inds_session", "fake-token")
    response = api.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "not logged in"