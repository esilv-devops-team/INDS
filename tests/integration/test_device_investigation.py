from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import Administrator, Device, Incident, MonitoringRun, TrafficSummary
from backend.services import traffic_activity


def test_device_traffic_history_is_scoped_and_bucketed(admin_api, database, monkeypatch):
    now = datetime(2026, 11, 19, 10, 2)
    monkeypatch.setattr(traffic_activity, "utc_now", lambda: now)
    engine, _, _ = database
    with Session(engine) as session, session.begin():
        admin = session.scalar(select(Administrator))
        device = Device(mac_address="02:00:00:00:00:01")
        other = Device(mac_address="02:00:00:00:00:02")
        run = MonitoringRun(started_by=admin, started_at=now - timedelta(hours=2))
        session.add_all([device, other, run])
        session.flush()
        device_id = device.id
        for endpoint, minutes_ago, size in ((device, 4, 100), (device, 1, 200), (other, 1, 999), (device, 70, 999)):
            start = now - timedelta(minutes=minutes_ago)
            session.add(TrafficSummary(
                device=endpoint, monitoring_run=run, window_start=start,
                window_end=start + timedelta(minutes=1), bytes_received=size,
                bytes_sent=size // 2, packets_received=3, packets_sent=2,
            ))

    response = admin_api.get(f"/api/devices/{device_id}/traffic/history?window=1h")
    assert response.status_code == 200
    data = response.json()
    assert (data["download"], data["upload"], data["packets"]) == (300, 150, 10)
    assert data["bucket_minutes"] == 5
    assert len(data["buckets"]) == 12
    assert data["buckets"][-1]["seconds"] == 120
    assert data["buckets"][-1]["download"] == 200
    assert data["buckets"][-2]["download"] == 100
    assert admin_api.get("/api/devices/999999/traffic/history").status_code == 404


def test_incident_history_supports_device_filter_and_pagination(admin_api, database):
    engine, _, _ = database
    created_at = datetime(2026, 11, 19, 10)
    with Session(engine) as session, session.begin():
        device = Device(mac_address="02:00:00:00:00:01")
        session.add(device)
        session.flush()
        device_id = device.id
        for source in (device, device, None):
            session.add(Incident(
                source_device=source, rule_code="port_scan", severity="High",
                source_ip="192.0.2.1", target_ip="192.0.2.2", created_at=created_at,
            ))

    path = f"/api/incidents?source_device_id={device_id}&status=open&limit=1"
    latest = admin_api.get(path).json()
    older = admin_api.get(path + "&offset=1").json()
    assert len(latest) == len(older) == 1
    assert latest[0]["id"] > older[0]["id"]
    assert latest[0]["source_device_id"] == older[0]["source_device_id"] == device_id
    assert admin_api.get(path + "&offset=2").json() == []
