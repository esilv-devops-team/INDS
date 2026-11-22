from datetime import UTC, datetime, timedelta

import pytest

from detection.registry import port_scan_rules
from detection.rules import port_scan
from detection.rules.port_scan import PortProbe, PortScanRule, PortScanSettings

ATTACKER = "192.168.50.66"
CAMERA = "192.168.50.20"
LAPTOP = "192.168.50.11"
START = datetime(2026, 11, 22, 10, tzinfo=UTC)


def probe(port, seconds=0, source=ATTACKER, target=CAMERA, mac="02:00:00:00:00:66"):
    return PortProbe(START + timedelta(seconds=seconds), source, target, port, "TCP", mac, 7)


def run(rule, probes):
    return [finding for finding in (rule.evaluate(item) for item in probes) if finding]


def test_twenty_ports_in_a_few_seconds_is_a_port_scan():
    rule = PortScanRule(PortScanSettings())
    findings = run(rule, [probe(port, seconds=port) for port in range(1, 21)])
    finding, = findings
    assert finding.rule_id == "PORT_SCAN"
    assert finding.source_device_id == 7
    assert finding.source_mac == "02:00:00:00:00:66"
    assert finding.severity == "Medium"
    assert finding.timestamp == START + timedelta(seconds=20)
    assert finding.measured == {"distinct_ports": 20}
    assert finding.evidence["target_ip"] == CAMERA
    assert finding.evidence["sample_ports"] == "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"


def test_nineteen_ports_or_repeated_ports_are_normal():
    assert run(PortScanRule(PortScanSettings()), [probe(port) for port in range(1, 20)]) == []
    assert run(PortScanRule(PortScanSettings()), [probe(443, seconds=second) for second in range(100)]) == []


def test_slow_scan_outside_the_window_is_ignored():
    rule = PortScanRule(PortScanSettings())
    assert run(rule, [probe(port, seconds=port * 4) for port in range(1, 30)]) == []


def test_ports_are_counted_per_source_and_target():
    rule = PortScanRule(PortScanSettings())
    probes = [probe(port, target=CAMERA) for port in range(1, 11)]
    probes += [probe(port, target=LAPTOP) for port in range(11, 21)]
    probes += [probe(port, source="192.168.50.67") for port in range(11, 21)]
    assert run(rule, probes) == []


def test_settings_change_the_threshold_and_severity():
    rule = PortScanRule(PortScanSettings(distinct_ports=5, window_seconds=10, severity="High"))
    finding, = run(rule, [probe(port, seconds=port) for port in range(1, 6)])
    assert finding.severity == "High"
    assert finding.evidence["distinct_ports_limit"] == 5


def test_engine_cooldown_and_disabled_rule():
    engine = port_scan_rules(PortScanSettings(distinct_ports=3))
    findings = []
    for port in range(1, 10):
        findings += engine.evaluate(probe(port, seconds=port))
    assert len(findings) == 1
    assert port_scan_rules(PortScanSettings(enabled=False)).rules == ()


def test_old_pairs_are_forgotten(monkeypatch):
    monkeypatch.setattr(port_scan, "MAX_TRACKED_PAIRS", 3)
    rule = PortScanRule(PortScanSettings())
    for number in range(3):
        rule.evaluate(probe(80, target=f"10.0.0.{number}"))
    rule.evaluate(probe(80, seconds=120, target="10.0.0.9"))
    assert list(rule.recent) == [(ATTACKER, "10.0.0.9")]


@pytest.mark.parametrize("values", [{"distinct_ports": 1}, {"window_seconds": 0}, {"cooldown_seconds": 0}, {"severity": "Huge"}])
def test_invalid_settings(values):
    with pytest.raises(ValueError):
        PortScanSettings(**values)