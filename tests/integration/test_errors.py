from fastapi.testclient import TestClient

from backend.database.session import get_session
from backend.main import app


def test_unknown_route_uses_error_format():
    response = TestClient(app).get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"error": {"status": 404, "message": "Not Found"}}


def test_server_error_hides_details():
    def broken_session():
        raise RuntimeError("database is down")
        yield

    app.dependency_overrides[get_session] = broken_session
    try:
        response = TestClient(app, raise_server_exceptions=False).get("/api/devices")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json() == {"error": {"status": 500, "message": "internal server error"}}