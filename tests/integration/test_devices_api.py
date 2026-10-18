"""Integration tests for GET /api/devices/vendor/{mac} (INDS-40)."""

from fastapi.testclient import TestClient

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