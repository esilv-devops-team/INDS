import json
from datetime import UTC, datetime
from threading import Event
from unittest.mock import Mock

import pytest
from scapy.all import IP, TCP, Ether
from sqlalchemy.orm import Session

from backend import main
from backend.database.models import Device
from backend.services import monitoring
from backend.services.detection_rules import port_scan_settings, update_rule
from gateway.traffic import read_metadata

ATTACKER = "02:00:00:00:00:66"


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


def syn(port):
    frame = Ether(bytes(Ether(src=ATTACKER, dst="02:00:00:00:00:01") / IP(src="192.168.50.66", dst="192.168.50.20") / TCP(dport=port, flags="S")))
    frame.sniffed_on = "ap0"
    frame.time = datetime.now(UTC).timestamp() + 1
    return read_metadata(frame)


def test_settings_come_from_the_port_scan_rule(database):
    engine, _, _ = database
    with Session(engine) as session:
        update_rule(session, "PORT_SCAN", {"distinct_ports": 8, "severity": "High"})
        settings = port_scan_settings(session)
    assert (settings.distinct_ports, settings.window_seconds, settings.severity) == (8, 60, "High")


def test_monitoring_logs_a_port_scan(admin_api, database, controller, monkeypatch, caplog):
    engine, _, _ = database
    with Session(engine) as session:
        session.add(Device(mac_address=ATTACKER))
        session.commit()
        update_rule(session, "PORT_SCAN", {"distinct_ports": 5})

    done = Event()

    def capture(interface, sock, receive, discoveries):
        if done.is_set():
            controller.stop_event.wait(5)
            return
        for port in range(20, 26):
            receive(syn(port))
        done.set()

    monkeypatch.setattr(monitoring, "open_capture", Mock(return_value=Mock()))
    monkeypatch.setattr(monitoring, "capture_batch", capture)
    caplog.set_level("WARNING", logger="backend.services.monitoring")

    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    assert done.wait(5)
    for _ in range(50):
        if "PORT_SCAN" in caplog.text:
            break
        controller.stop_event.wait(0.1)
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204

    finding = json.loads(next(r.getMessage() for r in caplog.records if "PORT_SCAN" in r.getMessage()).split(": ", 1)[1])
    assert finding["rule_id"] == "PORT_SCAN"
    assert finding["measured"] == {"distinct_ports": 5}
    assert finding["source_mac"] == ATTACKER