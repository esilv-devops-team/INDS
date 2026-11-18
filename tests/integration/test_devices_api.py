from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AuditEvent, Incident
from backend.main import app

client = TestClient(app)


def test_vendor_endpoint_known_mac():
    response = client.get("/api/devices/vendor/b8-27-eb-12-34-56")
    assert response.status_code == 200
    assert response.json() == {"mac": "B8:27:EB:12:34:56", "vendor": "Raspberry Pi Foundation"}


def test_vendor_endpoint_unknown_mac():
    response = client.get("/api/devices/vendor/00:11:22:33:44:55")
    assert response.status_code == 200
    assert response.json()["vendor"] == "Unknown"


def test_vendor_endpoint_invalid_mac():
    response = client.get("/api/devices/vendor/not-a-mac")
    assert response.status_code == 422


def test_post_and_get_devices(admin_api):
    api = admin_api
    response = api.post("/api/devices/observations", json={"observations": [
        {"mac": "b8:27:eb:12:34:56", "ip": "192.168.1.20", "hostname": "pi"},
        {"mac": "00:11:22:33:44:55"},
    ]})
    assert response.status_code == 200
    assert response.json() == {"received": 2, "new": 2}

    response = api.post("/api/devices/observations", json={"observations": [{"mac": "B8:27:EB:12:34:56"}]})
    assert response.json() == {"received": 1, "new": 0}

    devices = api.get("/api/devices").json()
    assert len(devices) == 2

    pi = [d for d in devices if d["mac_address"] == "B8:27:EB:12:34:56"][0]
    assert pi["current_ip"] == "192.168.1.20"
    assert pi["hostname"] == "pi"
    assert pi["vendor"] == "Raspberry Pi Foundation"

    response = api.get(f"/api/devices/{pi['id']}")
    assert response.status_code == 200
    assert response.json()["mac_address"] == "B8:27:EB:12:34:56"


def test_device_without_ip_or_hostname(admin_api):
    api = admin_api
    api.post("/api/devices/observations", json={"observations": [{"mac": "00:11:22:33:44:55"}]})
    device = api.get("/api/devices").json()[0]
    assert device["current_ip"] is None
    assert device["hostname"] is None


def test_invalid_mac_rejected(api):
    response = api.post("/api/devices/observations", json={"observations": [{"mac": "not-a-mac"}]})
    assert response.status_code == 422


def test_invalid_ip_rejected(api):
    response = api.post("/api/devices/observations", json={"observations": [{"mac": "00:11:22:33:44:55", "ip": "999.1.1.1"}]})
    assert response.status_code == 422


def test_device_not_found(admin_api):
    response = admin_api.get("/api/devices/999")
    assert response.status_code == 404
    assert response.json() == {"error": {"status": 404, "message": "device not found"}}


def test_devices_require_login(api):
    assert api.get("/api/devices").status_code == 401
    assert api.get("/api/devices/1").status_code == 401
    assert api.patch("/api/devices/1", json={"is_trusted": True}).status_code == 401


def test_trust_device(admin_api, database):
    engine, _, _ = database
    admin_api.post("/api/devices/observations", json={"observations": [{"mac": "00:11:22:33:44:55"}]})
    device = admin_api.get("/api/devices").json()[0]

    response = admin_api.patch(f"/api/devices/{device['id']}", json={"is_trusted": True})
    assert response.status_code == 200
    assert response.json()["is_trusted"] is True

    admin_api.patch(f"/api/devices/{device['id']}", json={"is_trusted": True})

    with Session(engine) as session:
        events = session.scalars(select(AuditEvent).where(AuditEvent.event_type == "device.trust_changed")).all()
        assert len(events) == 1
        assert events[0].device_id == device["id"]
        assert events[0].details_json == {"from": False, "to": True}


def test_trust_unknown_device(admin_api):
    response = admin_api.patch("/api/devices/999", json={"is_trusted": True})
    assert response.status_code == 404


def test_trust_needs_boolean(admin_api):
    response = admin_api.patch("/api/devices/1", json={"is_trusted": "maybe"})
    assert response.status_code == 422
    assert response.json()["error"]["fields"][0]["field"] == "is_trusted"



def test_devices_count_open_incidents(admin_api, database):
    engine, _, _ = database
    admin_api.post("/api/devices/observations", json={"observations": [{"mac": "00:11:22:33:44:55"}]})
    device_id = admin_api.get("/api/devices").json()[0]["id"]

    incident = {"source_device_id": device_id, "rule_code": "port_scan", "source_ip": "192.168.1.50", "target_ip": "192.168.1.10"}
    with Session(engine) as session:
        session.add(Incident(**incident))
        session.add(Incident(**incident, status="investigating"))
        session.add(Incident(**incident, status="resolved", resolved_at=utc_now() + timedelta(seconds=1)))
        session.commit()

    assert admin_api.get("/api/devices").json()[0]["open_incidents"] == 2
    assert admin_api.get(f"/api/devices/{device_id}").json()["open_incidents"] == 2