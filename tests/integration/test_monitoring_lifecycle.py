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
    assert admin_api.get("/api/system/status").json()["monitoring"] == "off"
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
    assert admin_api.get("/api/system/status").json()["monitoring"] == "off"
    with Session(engine) as session:
        assert session.scalar(select(MonitoringRun)).stop_reason == "failure"
    capture_socket.close.assert_called_once()


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
