import time
from datetime import timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, Incident, MonitoringRun, ResponseAction
from backend.services import live_traffic, monitoring
from backend.services.live_traffic import LiveFeed, WatchCapture
from gateway import traffic
from gateway.traffic import TrafficMetadata

ATTACKER = "02:00:00:00:00:66"
PHONE = "02:00:00:00:00:77"


def packet(mac=ATTACKER, when=None):
    return TrafficMetadata(
        interface="eth1", timestamp=when or time.time(), protocol="TCP", ip_protocol=6, source_mac=mac.lower(),
        destination_mac="02:00:00:00:00:01", source_ip="192.168.50.66", destination_ip="192.168.50.1",
        source_port=51000, destination_port=22, captured_bytes=60, tcp_flags="S",
    )


@pytest.fixture
def live(monkeypatch):
    feed = LiveFeed()
    watch = WatchCapture()
    monkeypatch.setattr(live_traffic, "feed", feed)
    monkeypatch.setattr("backend.api.live.feed", feed)
    monkeypatch.setattr("backend.api.live.watch", watch)
    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "eth1")
    monkeypatch.setattr(monitoring, "open_capture", Mock(return_value=Mock()))
    monkeypatch.setattr(traffic, "capture_traffic", lambda interfaces, on_metadata, duration, opened_socket: (
        live_traffic.feed.add(packet(), "watch"), time.sleep(0.01)))
    yield feed, watch
    watch.stop()


def test_live_requires_login(api):
    assert api.get("/api/live").status_code == 401
    assert api.post("/api/live/watch").status_code == 401
    assert api.delete("/api/live/watch").status_code == 401


def test_nothing_when_off(admin_api, live):
    body = admin_api.get("/api/live").json()
    assert (body["mode"], body["interface"], body["watch_seconds_left"]) == ("off", "eth1", None)
    assert (body["packets"], body["last"]) == ([], 0)
    assert len(body["rates"]) == 60


def test_watch_only_capture(admin_api, live):
    feed, watch = live
    started = admin_api.post("/api/live/watch")
    assert started.status_code == 200
    assert started.json()["mode"] == "watch"

    body = {}
    for _ in range(200):
        body = admin_api.get("/api/live").json()
        if body["packets"]:
            break
        time.sleep(0.01)
    first = body["packets"][0]
    assert body["mode"] == "watch"
    assert (first["mode"], first["incident_id"], first["dropped"]) == ("watch", None, False)
    assert first["source_mac"] == ATTACKER
    assert admin_api.get(f"/api/live?after={feed.since(0)[1] + 10}").json()["packets"] == []

    assert admin_api.delete("/api/live/watch").status_code == 204
    assert admin_api.get("/api/live").json()["mode"] == "off"


def test_watch_errors(admin_api, live, monkeypatch):
    monkeypatch.setattr(monitoring, "open_capture", Mock(side_effect=OSError("no device")))
    response = admin_api.post("/api/live/watch")
    assert (response.status_code, response.json()["error"]["message"]) == (503, "Unable to open traffic capture on eth1.")
    monkeypatch.delenv("INDS_MONITOR_INTERFACE")
    assert admin_api.post("/api/live/watch").status_code == 503


def test_marks_when_inds_is_on(admin_api, database, live):
    engine, _, _ = database
    feed, _ = live
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    now = utc_now()
    with Session(engine) as session, session.begin():
        run = MonitoringRun(started_by_id=admin_id, started_at=now - timedelta(minutes=10))
        attacker = Device(mac_address=ATTACKER, current_ip="192.168.50.66")
        incident = Incident(source_device=attacker, monitoring_run=run, rule_code="PORT_SCAN", source_ip="192.168.50.66",
                            target_ip="192.168.50.1", severity="High", risk_score=65,
                            first_seen_at=now - timedelta(minutes=2), last_seen_at=now - timedelta(minutes=1))
        session.add_all([run, incident])
        session.flush()
        session.add(ResponseAction(
            incident_id=incident.id, device_id=attacker.id, action_type="block", target_mac=ATTACKER,
            request_key="live-test", reason="AI: stop the scan", approval_status="approved", decided_by_id=admin_id,
            decided_at=now - timedelta(seconds=40), execution_status="active", applied_at=now - timedelta(seconds=30),
            created_at=now - timedelta(minutes=1),
        ))
        incident_id = incident.id

    current = time.time()
    feed.add(packet(when=current - 120), "watch")
    feed.add(packet(when=current - 60), "protect")
    feed.add(packet(when=current), "protect")
    feed.add(packet(mac=PHONE, when=current), "protect")

    body = admin_api.get("/api/live").json()
    assert body["mode"] == "protect"
    assert [(item["incident_id"], item["dropped"]) for item in body["packets"]] == [
        (None, False), (incident_id, False), (incident_id, True), (None, False),
    ]

    response = admin_api.post("/api/live/watch")
    assert (response.status_code, response.json()["error"]["message"]) == (
        409, "INDS is ON, the live view already uses its capture.")
