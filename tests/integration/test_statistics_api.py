from datetime import timedelta

from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, Incident, MonitoringRun, TrafficSummary
from backend.services.statistics import floor_time


def add_traffic(session, device, run, start, download, upload):
    session.add(TrafficSummary(
        device_id=device.id,
        monitoring_run_id=run.id,
        window_start=start,
        window_end=start + timedelta(minutes=1),
        bytes_received=download,
        bytes_sent=upload,
    ))


def fill_database(engine, admin_id):
    now = utc_now()
    this_hour = floor_time(now, timedelta(hours=1))
    with Session(engine) as session:
        run = MonitoringRun(started_by_id=admin_id, started_at=now - timedelta(days=2))
        laptop = Device(mac_address="00:11:22:33:44:55", hostname="laptop", current_ip="192.168.1.10",
                        first_seen_at=now - timedelta(days=3), last_seen_at=now)
        camera = Device(mac_address="28:57:BE:01:02:03", current_ip="192.168.1.30",
                        first_seen_at=this_hour, last_seen_at=now)
        session.add_all([run, laptop, camera])
        session.flush()

        add_traffic(session, laptop, run, this_hour, 3000, 1000)
        add_traffic(session, camera, run, this_hour, 500, 9000)
        add_traffic(session, laptop, run, this_hour - timedelta(hours=2), 2000, 0)
        add_traffic(session, laptop, run, this_hour - timedelta(days=2), 99999, 99999)

        incident = {"rule_code": "port_scan", "source_ip": "192.168.1.30", "target_ip": "192.168.1.10"}
        session.add(Incident(**incident, severity="High", created_at=this_hour, updated_at=this_hour))
        session.add(Incident(**incident, severity="Critical", created_at=this_hour, updated_at=this_hour))
        session.add(Incident(**incident, created_at=this_hour, updated_at=this_hour))
        old = now - timedelta(days=3)
        session.add(Incident(**incident, severity="Low", created_at=old, updated_at=old, first_seen_at=old, last_seen_at=old))
        session.commit()
    return this_hour


def test_statistics_require_login(api):
    assert api.get("/api/statistics").status_code == 401


def test_empty_statistics(admin_api):
    body = admin_api.get("/api/statistics").json()
    assert body["window"] == "24h"
    assert body["bucket_minutes"] == 60
    assert len(body["buckets"]) == 24
    assert body["buckets"][0]["seconds"] == 3600
    assert 0 < body["buckets"][-1]["seconds"] <= 3600
    assert body["totals"] == {"download": 0, "upload": 0, "active_devices": 0, "new_devices": 0, "incidents": 0}
    assert body["top_devices"] == []


def test_window_sizes(admin_api):
    one_hour = admin_api.get("/api/statistics", params={"window": "1h"}).json()
    assert (one_hour["bucket_minutes"], len(one_hour["buckets"])) == (5, 12)
    week = admin_api.get("/api/statistics", params={"window": "7d"}).json()
    assert (week["bucket_minutes"], len(week["buckets"])) == (360, 28)
    assert admin_api.get("/api/statistics", params={"window": "2y"}).status_code == 422


def test_statistics_with_data(admin_api, database):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    fill_database(engine, admin_id)

    body = admin_api.get("/api/statistics", params={"window": "24h"}).json()
    last = body["buckets"][-1]
    assert last["download"] == 3500
    assert last["upload"] == 10000
    assert last["active_devices"] == 2
    assert last["new_devices"] == 1
    assert last["incidents"] == 3
    assert (last["low"], last["high"], last["critical"]) == (0, 1, 1)
    assert body["buckets"][-3]["download"] == 2000

    assert body["totals"] == {"download": 5500, "upload": 10000, "active_devices": 2, "new_devices": 1, "incidents": 3}
    assert [device["name"] for device in body["top_devices"]] == ["28:57:BE:01:02:03", "laptop"]
    assert body["top_devices"][1] == {"id": 1, "name": "laptop", "ip": "192.168.1.10", "download": 5000, "upload": 1000, "total": 6000}

    week = admin_api.get("/api/statistics", params={"window": "7d"}).json()
    assert week["totals"]["download"] == 5500 + 99999
    assert week["totals"]["incidents"] == 4