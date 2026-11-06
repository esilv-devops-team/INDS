from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from backend.database.session import get_session
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

@pytest.fixture
def api(database):
    engine, _, _ = database

    def test_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_post_and_get_devices(api):
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


def test_device_without_ip_or_hostname(api):
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


def test_device_not_found(api):
    response = api.get("/api/devices/999")
    assert response.status_code == 404