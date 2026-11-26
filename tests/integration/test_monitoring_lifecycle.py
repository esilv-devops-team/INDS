from threading import Event
from time import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import main
from backend.database.base import utc_now
from backend.database.models import Administrator, AuditEvent, Device, MonitoringRun, TrafficSummary
from backend.services import monitoring

CLIENT = "02:00:00:00:00:01"
DISCOVERED = "02:00:00:00:00:02"


def test_restart_recovers_enabled_preference_and_respects_off(admin_api, database, controller, monkeypatch):
    engine = database[0]
    entered = Event()
    monkeypatch.setattr(monitoring, "open_capture", Mock(side_effect=lambda _: Mock()))

    def capture(*_):
        entered.set()
        controller.stop_event.wait(2)

    monkeypatch.setattr(monitoring, "capture_batch", capture)
    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    assert entered.wait(2)
    controller.shutdown()
    entered.clear()
    controller.recover(engine)
    assert entered.wait(2)
    assert admin_api.get("/api/system/status").json()["monitoring_configured"]
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    controller.recover(engine)
    assert not admin_api.get("/api/system/status").json()["monitoring_configured"]
    assert monitoring.open_capture.call_count == 2
    with Session(engine) as session:
        events = session.scalars(select(AuditEvent).where(AuditEvent.event_type == "monitoring.start")
                                 .order_by(AuditEvent.id)).all()
        assert events[-1].actor_type == "system"
        assert events[-1].details_json == {"recovered": True}


def test_recovery_failure_keeps_configured_intent_and_surfaces_error(admin_api, database, controller, monkeypatch):
    from backend.database.models import MonitoringPreference

    engine = database[0]
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    with Session(engine) as session, session.begin():
        session.add(MonitoringPreference(id=1, enabled_by_id=admin_id))
    monkeypatch.setattr(monitoring, "open_capture", Mock(side_effect=OSError("capture unavailable")))
    controller.recover(engine)
    status = admin_api.get("/api/system/status").json()
    assert status["monitoring"] == "off" and status["monitoring_configured"]
    assert "Unable to open traffic capture" in status["monitoring_recovery_error"]
    with Session(engine) as session:
        failure = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "monitoring.recovery_failed"))
        assert failure.outcome == "failure" and failure.actor_type == "system"


@pytest.fixture
def controller(monkeypatch):
    service = monitoring.MonitoringController()
    previous = main.app.state.monitoring
    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "ap0")
    main.app.state.monitoring = service
    try:
        yield service
    finally:
        main.app.state.monitoring = previous
        service.shutdown()


def test_start_collect_and_stop(admin_api, database, controller, monkeypatch):
    engine, _, _ = database
    with Session(engine) as session, session.begin():
        session.add(Device(mac_address=CLIENT))
    capture_socket = Mock()
    second_batch = Event()
    open_socket = Mock(return_value=capture_socket)
    monkeypatch.setattr(monitoring, "open_capture", open_socket)
    first_batch = True

    def capture(interface, sock, receive, discoveries):
        nonlocal first_batch
        assert (interface, sock) == ("ap0", capture_socket)
        receive(SimpleNamespace(
            source_mac=CLIENT, destination_mac=DISCOVERED,
            timestamp=time(), captured_bytes=120,
        ))
        if first_batch:
            first_batch = False
            discoveries[DISCOVERED] = {"mac": DISCOVERED}
            return
        second_batch.set()
        assert controller.stop_event.wait(5)

    monkeypatch.setattr(monitoring, "capture_batch", capture)
    monkeypatch.setattr(monitoring, "guest_observations", lambda _, devices: list(devices.values()))

    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    assert second_batch.wait(5)
    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    assert admin_api.get("/api/system/status").json()["monitoring"] == "on"
    assert admin_api.post("/api/devices/observations", json={"observations": []}).status_code == 409
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    status = admin_api.get("/api/system/status").json()
    assert status["monitoring"] == "off"
    assert status["monitoring_stop_reason"] == "administrator"
    open_socket.assert_called_once_with("ap0")
    capture_socket.close.assert_called_once()

    with Session(engine) as session:
        run = session.execute(select(MonitoringRun)).scalar_one()
        assert run.stop_reason == "administrator"
        assert run.stopped_by_id == run.started_by_id
        assert session.scalar(select(TrafficSummary)).bytes_sent == 120
        assert session.scalar(select(Device).where(Device.mac_address == DISCOVERED))
        assert list(session.scalars(select(AuditEvent.event_type).where(AuditEvent.monitoring_run_id == run.id))) == [
            "monitoring.start", "monitoring.stop",
        ]


def test_capture_open_and_worker_failures(admin_api, database, controller, monkeypatch):
    engine, _, _ = database
    with monkeypatch.context() as patch:
        patch.delenv("INDS_MONITOR_INTERFACE")
        assert admin_api.post("/api/system/monitoring/start").status_code == 503
    monkeypatch.setattr(monitoring, "open_capture", Mock(side_effect=OSError("no capture permission")))
    assert admin_api.post("/api/system/monitoring/start").status_code == 503
    with Session(engine) as session:
        assert session.scalar(select(MonitoringRun)) is None

    capture_socket = Mock()
    monkeypatch.setattr(monitoring, "open_capture", Mock(return_value=capture_socket))
    monkeypatch.setattr(monitoring, "capture_batch", Mock(side_effect=OSError("capture failed")))
    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    controller.worker.join(5)
    assert not controller.worker.is_alive()
    status = admin_api.get("/api/system/status").json()
    assert status["monitoring"] == "off"
    assert status["monitoring_stop_reason"] == "failure"
    with Session(engine) as session:
        assert session.scalar(select(MonitoringRun)).stop_reason == "failure"
    capture_socket.close.assert_called_once()


def test_routed_capture_counts_new_client_in_first_batch(admin_api, database, controller, monkeypatch, tmp_path):
    from gateway import discovery

    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "eth1")
    leases = tmp_path / "dnsmasq.leases"
    leases.write_text(f"0 {CLIENT} 192.168.50.101 phone *\n")
    monkeypatch.setenv("INDS_DHCP_LEASE_FILE", str(leases))
    monkeypatch.setattr(discovery, "read_neighbors", lambda _: [])
    monkeypatch.setattr(discovery, "macs_on_port", Mock(side_effect=AssertionError("bridge queried")))
    monkeypatch.setattr(monitoring, "open_capture", Mock(return_value=Mock()))
    captured = Event()

    def capture(_interface, _socket, receive, _discoveries):
        if captured.is_set():
            assert controller.stop_event.wait(5)
            return
        receive(SimpleNamespace(source_mac=CLIENT, destination_mac=DISCOVERED,
                                timestamp=time(), captured_bytes=120))
        captured.set()

    second_batch = Event()

    def observed_capture(*args):
        if captured.is_set():
            second_batch.set()
        capture(*args)

    monkeypatch.setattr(monitoring, "capture_batch", observed_capture)
    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    assert second_batch.wait(5)
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    device, = admin_api.get("/api/devices").json()
    assert device["ip_source"] == "dhcp_lease"
    assert device["last_active_at"] is not None
    with Session(database[0]) as session:
        assert session.scalar(select(TrafficSummary)).bytes_sent == 120


def test_startup_reconciles_interrupted_run(api, database, controller, monkeypatch):
    engine, _, _ = database
    monkeypatch.setattr(main, "get_engine", lambda: engine)
    with Session(engine) as session, session.begin():
        admin = Administrator(username="admin", password_hash="test")
        session.add(admin)
        session.flush()
        session.add(MonitoringRun(started_at=utc_now(), started_by_id=admin.id))

    with api as client:
        assert client.post("/api/system/monitoring/start").status_code == 401
        assert client.post("/api/system/monitoring/stop").status_code == 401
    with Session(engine) as session:
        run = session.scalar(select(MonitoringRun))
        assert run.stop_reason == "interrupted"
        assert session.scalar(select(AuditEvent)).monitoring_run_id == run.id
