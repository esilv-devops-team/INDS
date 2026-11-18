from datetime import timedelta

from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, MonitoringRun
from backend.services import gateway_health


def services_by_name(api):
    return {service["name"]: service for service in api.get("/api/gateway/health").json()["services"]}


def test_health_requires_login(api):
    assert api.get("/api/gateway/health").status_code == 401


def test_health_shape(admin_api):
    response = admin_api.get("/api/gateway/health")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"system", "interfaces", "services"}
    assert body["system"]["hostname"]
    assert all("lo" != item["name"] for item in body["interfaces"])


def test_services_with_nothing_running(admin_api, monkeypatch):
    monkeypatch.setattr(gateway_health, "read_interfaces", lambda: [])
    services = services_by_name(admin_api)
    assert services["Database"]["state"] == "ok"
    assert services["Discovery sniffer"] == {"name": "Discovery sniffer", "state": "down", "detail": "never sent a report"}
    assert services["Bridge br-inds"]["detail"] == "interface not found on this machine"
    assert services["Monitoring"]["state"] == "warn"


def test_services_when_running(admin_api, database, monkeypatch):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    with Session(engine) as session:
        session.add(Device(mac_address="00:11:22:33:44:55"))
        session.add(MonitoringRun(started_by_id=admin_id))
        session.commit()

    bridge = {"name": "br-inds", "is_up": True, "is_bridge": True}
    monkeypatch.setattr(gateway_health, "read_interfaces", lambda: [bridge])
    services = services_by_name(admin_api)
    assert services["Discovery sniffer"]["state"] == "ok"
    assert services["Bridge br-inds"]["state"] == "ok"
    assert services["Monitoring"]["detail"] == "running"

    bridge["is_up"] = False
    assert services_by_name(admin_api)["Bridge br-inds"]["detail"] == "interface is down"


def test_discovery_silent_for_too_long(admin_api, database):
    engine, _, _ = database
    old = utc_now() - timedelta(minutes=10)
    with Session(engine) as session:
        session.add(Device(mac_address="00:11:22:33:44:55", first_seen_at=old, last_seen_at=old))
        session.commit()

    service = services_by_name(admin_api)["Discovery sniffer"]
    assert service["state"] == "down"
    assert service["detail"] == "no report for 10 min"