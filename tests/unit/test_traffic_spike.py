from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from detection.engine import DetectionEngine
from detection.registry import traffic_rules
from detection.rules.traffic_spike import TrafficSpikeRule, TrafficSpikeSettings, TrafficWindow

START = datetime(2026, 11, 20, tzinfo=UTC)
SETTINGS = TrafficSpikeSettings(window_minutes=2, max_bytes_per_minute=100, max_packets_per_minute=10)


def traffic(device=1, minute=0, *, received=0, packets=0, length=2):
    start = START + timedelta(minutes=minute)
    return TrafficWindow(device, start, start + timedelta(minutes=length), 100, received, 10, packets)


@pytest.mark.parametrize(("received", "packets", "trigger"), [
    (100, 10, None),
    (101, 10, "bytes"),
    (100, 11, "packets"),
    (101, 11, "bytes_and_packets"),
])
def test_spike_checks_both_rates_and_reports_evidence(received, packets, trigger):
    finding = TrafficSpikeRule(SETTINGS).evaluate(traffic(received=received, packets=packets))
    if trigger is None:
        assert finding is None
    else:
        assert finding.rule_id == "TRAFFIC_SPIKE"
        assert finding.source_device_id == 1
        assert finding.severity == "Medium"
        assert finding.timestamp == START + timedelta(minutes=2)
        assert finding.evidence["trigger"] == trigger
        assert finding.measured["bytes_per_minute"] == (100 + received) / 2
        assert finding.measured["packets_per_minute"] == (10 + packets) / 2


def test_incomplete_windows_do_not_trigger():
    assert TrafficSpikeRule(SETTINGS).evaluate(traffic(received=500, length=1)) is None


def test_cooldown_is_per_device_and_releases_at_boundary():
    engine = traffic_rules(SETTINGS)
    assert engine.evaluate(traffic(received=200))
    assert engine.evaluate(traffic(received=200)) == []
    assert engine.evaluate(traffic(minute=2, received=200)) == []
    assert engine.evaluate(traffic(device=2, minute=2, received=200))
    assert engine.evaluate(traffic(minute=5, received=200))


def test_registry_respects_disabled_rule_and_duplicate_ids():
    assert traffic_rules(replace(SETTINGS, enabled=False)).evaluate(traffic(received=200)) == []
    rule = TrafficSpikeRule(SETTINGS)
    with pytest.raises(ValueError, match="unique"):
        DetectionEngine((rule, rule))


@pytest.mark.parametrize("overrides", [
    {"window_minutes": 0}, {"window_minutes": 61}, {"max_bytes_per_minute": 0},
    {"max_packets_per_minute": -1}, {"cooldown_seconds": 0},
])
def test_rejects_invalid_settings(overrides):
    with pytest.raises(ValueError):
        replace(SETTINGS, **overrides)
