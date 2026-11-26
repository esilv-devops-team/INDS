from datetime import UTC, datetime, timedelta
from threading import Event
from unittest.mock import Mock

import pytest
from scapy.all import IP, TCP, Ether
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import main
from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Device, Incident, MonitoringRun
from backend.services import monitoring
from backend.services.detection_rules import update_rule
from backend.services.incident_creation import record_findings
from detection.base import Finding
from gateway.traffic import read_metadata

SCANNER = "02:00:00:00:00:66"
NOW = utc_now().replace(microsecond=0)


def port_scan(device_id=None, minutes=0, mac=SCANNER, target="192.168.50.20"):
    return Finding(
        rule_id="PORT_SCAN",
        source_device_id=device_id,
        timestamp=(NOW + timedelta(minutes=minutes)).replace(tzinfo=UTC),
        severity="Medium",
        evidence={"source_ip": "192.168.50.66", "target_ip": target, "protocol": "TCP", "sample_ports": "21,22,23"},
        measured={"distinct_ports": 20},
        source_mac=mac,
    )


def prepare(engine, trusted=False, device_age_hours=5):
    with Session(engine) as session:
        admin = Administrator(username="setup", password_hash="x")
        session.add(admin)
        session.flush()
        run = MonitoringRun(started_by_id=admin.id, started_at=NOW - timedelta(hours=1))
        first_seen = NOW - timedelta(hours=device_age_hours)
        device = Device(mac_address=SCANNER, current_ip="192.168.50.66", is_trusted=trusted,
                        first_seen_at=first_seen, last_seen_at=NOW)
        session.add_all([run, device])
        session.commit()
        return run.id, device.id


def record(engine, run_id, findings):
    with Session(engine) as session, session.begin():
        return [(incident.id, created) for incident, created in record_findings(session, run_id, findings)]


def load(engine, incident_id):
    with Session(engine) as session:
        incident = session.get(Incident, incident_id)
        session.expunge(incident)
        return incident


def test_finding_becomes_an_open_incident(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    (incident_id, created), = record(engine, run_id, [port_scan(device_id)])
    assert created

    incident = load(engine, incident_id)
    assert (incident.rule_code, incident.status, incident.severity, incident.risk_score) == ("PORT_SCAN", "open", "Medium", 40)
    assert (incident.source_ip, incident.target_ip) == ("192.168.50.66", "192.168.50.20")
    assert (incident.source_device_id, incident.monitoring_run_id) == (device_id, run_id)
    assert incident.first_seen_at == NOW
    assert incident.evidence_json == {
        "source_ip": "192.168.50.66", "target_ip": "192.168.50.20", "protocol": "TCP",
        "sample_ports": "21,22,23", "distinct_ports": 20, "rule_severity": "Medium", "occurrences": 1,
    }
    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "incident.created"))
        assert event.incident_id == incident_id
        assert event.details_json == {"rule": "PORT_SCAN", "severity": "Medium", "risk_score": 40}


def test_new_device_and_trusted_device(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine, device_age_hours=0)
    (incident_id, _), = record(engine, run_id, [port_scan(device_id)])
    assert load(engine, incident_id).risk_score == 50

    with Session(engine) as session:
        session.get(Device, device_id).is_trusted = True
        session.get(Incident, incident_id).status = "resolved"
        session.get(Incident, incident_id).resolved_at = NOW + timedelta(hours=1)
        session.commit()
    (second_id, created), = record(engine, run_id, [port_scan(device_id)])
    assert created and second_id != incident_id
    assert load(engine, second_id).severity == "Low"


def test_repeats_are_grouped_and_escalate(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    findings = [port_scan(device_id, minutes=minute) for minute in (0, 5, 10, 15, 20)]
    results = record(engine, run_id, findings)
    assert [created for _, created in results] == [True, False, False, False, False]

    incident = load(engine, results[0][0])
    assert incident.evidence_json["occurrences"] == 5
    assert incident.last_seen_at == NOW + timedelta(minutes=20)
    assert (incident.risk_score, incident.severity) == (55, "High")

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "incident.escalated"))
        assert event.details_json == {"from": "Medium", "to": "High", "risk_score": 55}


def test_new_incident_after_the_window_or_for_another_target(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    results = record(engine, run_id, [
        port_scan(device_id), port_scan(device_id, minutes=11), port_scan(device_id, minutes=12, target="192.168.50.30"),
    ])
    assert [created for _, created in results] == [True, True, True]


def test_other_rules_and_unknown_devices(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    arp = Finding("ARP_SPOOFING", None, NOW.replace(tzinfo=UTC), "High",
                  {"sender_ip": "192.168.50.1", "expected_mac": "02:00:00:00:00:01", "claimed_mac": SCANNER},
                  {"arp_operation": 2}, source_mac=SCANNER.lower())
    spike = Finding("TRAFFIC_SPIKE", device_id, NOW, "Medium", {"trigger": "bytes"}, {"bytes_per_minute": 9e8})
    stranger = port_scan(mac="02:00:00:00:00:77")
    results = record(engine, run_id, [arp, spike, stranger])

    arp_incident, spike_incident, stranger_incident = (load(engine, incident_id) for incident_id, _ in results)
    assert (arp_incident.source_device_id, arp_incident.source_ip, arp_incident.target_ip) == (device_id, "192.168.50.66", "192.168.50.1")
    assert (arp_incident.risk_score, arp_incident.severity) == (65, "High")
    assert (spike_incident.source_ip, spike_incident.target_ip) == ("192.168.50.66", "multiple")
    assert stranger_incident.source_device_id is None

    nobody = Finding("TRAFFIC_SPIKE", 999, NOW, "Low", {}, {})
    (incident_id, _), = record(engine, run_id, [nobody])
    assert (load(engine, incident_id).source_ip, load(engine, incident_id).source_device_id) == ("unknown", None)


def test_no_incident_after_monitoring_stopped(database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    with Session(engine) as session:
        run = session.get(MonitoringRun, run_id)
        run.ended_at, run.stop_reason = NOW, "shutdown"
        session.commit()
    assert record(engine, run_id, [port_scan(device_id)]) == []
    assert record(engine, 999, [port_scan(device_id)]) == []


def test_new_incident_queues_one_analysis(admin_api, database):
    engine, _, _ = database
    run_id, device_id = prepare(engine)
    (incident_id, _), = record(engine, run_id, [port_scan(device_id)])
    record(engine, run_id, [port_scan(device_id, minutes=1), port_scan(device_id, minutes=2)])

    detail = admin_api.get(f"/api/incidents/{incident_id}").json()
    analysis, = detail["analyses"]
    assert (analysis["model"], analysis["status"], analysis["assessment"]) == ("deepseek-flash", "pending", None)

    with Session(engine) as session:
        assert session.scalar(select(AIAnalysis)).input_summary_json == {}


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
    frame = Ether(bytes(Ether(src=SCANNER, dst="02:00:00:00:00:01") / IP(src="192.168.50.66", dst="192.168.50.20") / TCP(dport=port, flags="S")))
    frame.sniffed_on = "ap0"
    frame.time = datetime.now(UTC).timestamp() + 1
    return read_metadata(frame)


def test_monitoring_creates_incidents(admin_api, database, controller, monkeypatch):
    engine, _, _ = database
    with Session(engine) as session:
        session.add(Device(mac_address=SCANNER))
        session.commit()
        update_rule(session, "PORT_SCAN", {"distinct_ports": 5})

    sent = Event()

    def capture(interface, sock, receive, discoveries):
        if sent.is_set():
            controller.stop_event.wait(5)
            return
        for port in range(20, 26):
            receive(syn(port))
        sent.set()

    monkeypatch.setattr(monitoring, "open_capture", Mock(return_value=Mock()))
    monkeypatch.setattr(monitoring, "capture_batch", capture)

    assert admin_api.post("/api/system/monitoring/start").status_code == 204
    incidents = []
    for _ in range(50):
        incidents = admin_api.get("/api/incidents").json()
        if incidents:
            break
        controller.stop_event.wait(0.1)
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204

    incident, = incidents
    assert (incident["rule_code"], incident["severity"], incident["status"]) == ("PORT_SCAN", "Medium", "open")
    assert incident["target_ip"] == "192.168.50.20"