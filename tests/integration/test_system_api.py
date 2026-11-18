from datetime import timedelta

from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, Incident, MonitoringRun


def test_status_requires_login(api):
    assert api.get("/api/system/status").status_code == 401


def test_status_when_empty(admin_api):
    body = admin_api.get("/api/system/status").json()
    assert body["monitoring"] == "off"
    assert body["monitoring_since"] is None
    assert body["devices"] == 0
    assert body["online_devices"] == 0
    assert body["last_device_seen_at"] is None
    assert body["open_incidents"] == 0
    assert body["open_by_severity"] == {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}


def test_status_with_data(admin_api, database):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    now = utc_now()

    with Session(engine) as session:
        session.add(MonitoringRun(started_by_id=admin_id))
        session.add(Device(mac_address="00:11:22:33:44:55", first_seen_at=now, last_seen_at=now))
        session.add(Device(
            mac_address="00:11:22:33:44:66",
            first_seen_at=now - timedelta(hours=2),
            last_seen_at=now - timedelta(hours=1),
        ))
        incident = {"rule_code": "port_scan", "source_ip": "192.168.1.50", "target_ip": "192.168.1.10"}
        session.add(Incident(**incident, severity="High"))
        session.add(Incident(**incident, severity="High"))
        session.add(Incident(**incident, severity="Critical"))
        session.add(Incident(**incident))
        session.add(Incident(**incident, severity="Low", status="resolved", resolved_at=now + timedelta(seconds=1)))
        session.commit()

    body = admin_api.get("/api/system/status").json()
    assert body["monitoring"] == "on"
    assert body["monitoring_since"] is not None
    assert body["devices"] == 2
    assert body["online_devices"] == 1
    assert body["open_incidents"] == 3
    assert body["open_by_severity"] == {"Low": 0, "Medium": 0, "High": 2, "Critical": 1}