from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Administrator, Device, Incident, MonitoringRun, TrafficSummary
from backend.services.ai_context import build_context, describe_address

NOW = utc_now().replace(microsecond=0)
SCANNER = "02:00:00:00:00:66"
CAMERA = "3C:22:FB:00:00:20"
PHONE = "02:00:00:00:00:77"


def add_run(session):
    admin = Administrator(username="setup", password_hash="x")
    session.add(admin)
    session.flush()
    run = MonitoringRun(started_by_id=admin.id, started_at=NOW - timedelta(days=2))
    session.add(run)
    session.flush()
    return run


def add_device(session, mac, ip, hours=5, **extra):
    device = Device(mac_address=mac, current_ip=ip, first_seen_at=NOW - timedelta(hours=hours), last_seen_at=NOW, **extra)
    session.add(device)
    session.flush()
    return device


def add_incident(session, device, rule="PORT_SCAN", minutes=0, source_ip="192.168.50.66",
                 target_ip="192.168.50.20", evidence=None, status="open"):
    incident = Incident(
        source_device_id=device.id if device is not None else None, rule_code=rule, source_ip=source_ip,
        target_ip=target_ip, first_seen_at=NOW + timedelta(minutes=minutes),
        last_seen_at=NOW + timedelta(minutes=minutes + 2), risk_score=40, severity="Medium", status=status,
        resolved_at=NOW + timedelta(days=1) if status == "resolved" else None,
        evidence_json=evidence or {"source_ip": source_ip, "target_ip": target_ip, "protocol": "TCP",
                                   "sample_ports": "21,22,23", "distinct_ports": 20,
                                   "rule_severity": "Medium", "occurrences": 3},
    )
    session.add(incident)
    session.flush()
    return incident


def add_traffic(session, run, device, minutes_before, sent, packets):
    start = NOW - timedelta(minutes=minutes_before)
    session.add(TrafficSummary(
        device_id=device.id, monitoring_run_id=run.id, window_start=start, window_end=start + timedelta(minutes=1),
        bytes_sent=sent, bytes_received=sent // 2, packets_sent=packets, packets_received=packets // 2,
        connection_count=4,
    ))


def leaks(context, *values):
    text = str(context)
    return [value for value in values if value and value in text]


def test_port_scan_context(database):
    engine, _, _ = database
    with Session(engine) as session:
        add_run(session)
        scanner = add_device(session, SCANNER, "192.168.50.66", hours=0.5, hostname="kali-laptop", vendor="Randomized")
        camera = add_device(session, CAMERA, "192.168.50.20", hostname="living-room-cam", vendor="Hikvision", is_trusted=True)
        incident = add_incident(session, scanner)
        context = build_context(session, incident)

    assert context["threat_type"] == "PORT_SCAN"
    assert (context["source"], context["target"]) == (f"device-{scanner.id}", f"device-{camera.id}")
    assert context["occurrences"] == 3
    assert context["evidence"] == {"source": f"device-{scanner.id}", "target": f"device-{camera.id}", "protocol": "TCP",
                                   "sample_ports": "21,22,23", "distinct_ports": 20,
                                   "rule_severity": "Medium", "occurrences": 3}
    assert context["device"] == {
        "ref": f"device-{scanner.id}", "vendor": "Randomized", "trusted": False,
        "first_seen_at": (NOW - timedelta(hours=0.5)).isoformat(), "minutes_known_before_incident": 30,
        "new_device": True, "other_open_incidents": 0,
    }
    assert context["previous_incidents"] == []
    assert leaks(context, "192.168.50.66", "192.168.50.20", SCANNER, CAMERA, "kali-laptop", "living-room-cam") == []


def test_arp_spoofing_context(database):
    engine, _, _ = database
    with Session(engine) as session:
        add_run(session)
        attacker = add_device(session, PHONE, "192.168.50.77")
        camera = add_device(session, CAMERA, "192.168.50.20")
        evidence = {"sender_ip": "192.168.50.20", "expected_mac": CAMERA, "claimed_mac": PHONE,
                    "arp_operation": 2, "rule_severity": "High", "occurrences": 1}
        incident = add_incident(session, attacker, rule="ARP_SPOOFING", source_ip="192.168.50.77",
                                target_ip="192.168.50.20", evidence=evidence)
        context = build_context(session, incident)

    assert context["evidence"] == {"sender": f"device-{camera.id}", "expected": f"device-{camera.id}",
                                   "claimed": f"device-{attacker.id}", "arp_operation": 2,
                                   "rule_severity": "High", "occurrences": 1}
    assert leaks(context, "192.168.50.77", "192.168.50.20", PHONE, CAMERA) == []


def test_traffic_spike_context(database):
    engine, _, _ = database
    with Session(engine) as session:
        run = add_run(session)
        device = add_device(session, PHONE, "192.168.50.77", hours=30)
        for minutes_before in (100, 200, 300, 400):
            add_traffic(session, run, device, minutes_before, 1000, 10)
        add_traffic(session, run, device, 5, 900000, 7000)
        add_traffic(session, run, device, -1, 800000, 6000)
        add_traffic(session, run, device, -60, 5, 1)
        evidence = {"trigger": "bytes", "window_start": NOW.isoformat(), "bytes_per_minute": 850000,
                    "rule_severity": "Medium", "occurrences": 2}
        incident = add_incident(session, device, rule="TRAFFIC_SPIKE", target_ip="multiple", evidence=evidence)
        context = build_context(session, incident)

    assert context["target"] == "multiple targets"
    traffic = context["traffic"]
    assert traffic["minutes_measured"] == 2
    assert traffic["during_incident"] == {"bytes_sent": 1700000, "bytes_received": 850000, "packets_sent": 13000,
                                          "packets_received": 6500, "connection_count": 8}
    assert traffic["usual_per_minute"] == {"bytes_sent": 1000, "bytes_received": 500, "packets_sent": 10,
                                           "packets_received": 5, "connection_count": 4}
    assert context["device"]["new_device"] is False


def test_no_usual_traffic_and_no_device(database):
    engine, _, _ = database
    with Session(engine) as session:
        add_run(session)
        device = add_device(session, PHONE, "192.168.50.77")
        incident = add_incident(session, device)
        context = build_context(session, incident)
        assert context["traffic"] == {"minutes_measured": 0, "usual_per_minute": None, "during_incident": {
            "bytes_sent": 0, "bytes_received": 0, "packets_sent": 0, "packets_received": 0, "connection_count": 0}}

        unknown = add_incident(session, None, source_ip="192.168.50.99", target_ip="8.8.8.8")
        context = build_context(session, unknown)
    assert (context["source"], context["target"]) == ("lan host", "external host")
    assert (context["device"], context["traffic"], context["previous_incidents"]) == (None, None, [])
    assert leaks(context, "192.168.50.99", "8.8.8.8") == []


def test_previous_incidents(database):
    engine, _, _ = database
    with Session(engine) as session:
        add_run(session)
        device = add_device(session, PHONE, "192.168.50.77", hours=48)
        other = add_device(session, SCANNER, "192.168.50.66")
        for number in range(7):
            add_incident(session, device, minutes=-600 + number * 60, status="resolved")
        add_incident(session, other, minutes=-30)
        incident = add_incident(session, device)
        add_incident(session, device, rule="TRAFFIC_SPIKE", minutes=10)
        context = build_context(session, incident)

    previous = context["previous_incidents"]
    assert len(previous) == 5
    assert [item["first_seen_at"] for item in previous] == [
        (NOW + timedelta(minutes=-600 + number * 60)).isoformat() for number in (6, 5, 4, 3, 2)
    ]
    assert previous[0] == {"threat_type": "PORT_SCAN", "severity": "Medium", "risk_score": 40, "status": "resolved",
                           "occurrences": 3, "first_seen_at": (NOW - timedelta(minutes=240)).isoformat()}
    assert context["device"]["other_open_incidents"] == 1


@pytest.mark.parametrize("value, expected", [
    (None, "unknown"),
    ("unknown", "unknown"),
    ("multiple", "multiple targets"),
    ("not an address", "unknown"),
    ("10.0.0.8", "lan host"),
    ("fe80::1", "lan host"),
    ("1.1.1.1", "external host"),
    ("02:00:00:00:00:99", "unknown device"),
    ("02:00:00:00:00:aa", "access point"),
])
def test_describe_address(database, monkeypatch, value, expected):
    engine, _, _ = database
    monkeypatch.setenv("INDS_MONITOR_AP_MAC", "02:00:00:00:00:AA")
    with Session(engine) as session:
        assert describe_address(session, value) == expected
