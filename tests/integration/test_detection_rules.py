import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import manage_rules
from backend.database.models import AuditEvent, DetectionRule
from backend.services.detection_rules import (
    arp_spoofing_settings, get_rule, traffic_spike_settings, update_rule, validate_settings,
)
from detection.rules.traffic_spike import TrafficSpikeSettings

ROUTER_BINDING = {"192.168.1.1": "b8-27-eb-12-34-56"}


def test_migration_adds_default_rules(database):
    engine, _, _ = database
    with Session(engine) as session:
        rules = {rule.rule_code: rule for rule in session.scalars(select(DetectionRule))}
        assert set(rules) == {"TRAFFIC_SPIKE", "ARP_SPOOFING", "PORT_SCAN"}
        assert rules["PORT_SCAN"].settings_json == {"distinct_ports": 20, "window_seconds": 60}
        assert all(rule.enabled and rule.cooldown_seconds == 300 for rule in rules.values())
        for rule in rules.values():
            validate_settings(rule.rule_code, rule.settings_json)


def test_rules_api(api, admin_api):
    response = admin_api.get("/api/detection/rules")
    assert response.status_code == 200
    rules = response.json()
    assert [rule["rule_code"] for rule in rules] == ["ARP_SPOOFING", "PORT_SCAN", "TRAFFIC_SPIKE"]
    assert rules[2]["settings"]["max_packets_per_minute"] == 100000
    assert rules[0]["severity"] == "High"

    admin_api.post("/api/auth/logout")
    assert admin_api.get("/api/detection/rules").status_code == 401


def test_update_rule_and_audit(database):
    engine, _, _ = database
    with Session(engine) as session:
        update_rule(session, "PORT_SCAN", {"distinct_ports": 30, "severity": "High", "enabled": False})
        rule = get_rule(session, "PORT_SCAN")
        assert (rule.enabled, rule.severity, rule.settings_json) == (False, "High", {"distinct_ports": 30, "window_seconds": 60})

        update_rule(session, "PORT_SCAN", {"distinct_ports": 30})
        events = session.scalars(select(AuditEvent).where(AuditEvent.event_type == "detection_rule.updated")).all()
        assert len(events) == 1
        assert events[0].actor_type == "system"
        assert events[0].details_json == {
            "rule": "PORT_SCAN",
            "changes": {"enabled": False, "severity": "High", "settings": {"distinct_ports": 30, "window_seconds": 60}},
        }


@pytest.mark.parametrize("rule_code, changes", [
    ("PORT_SCAN", {"distinct_ports": 1}),
    ("PORT_SCAN", {"distinct_ports": "20"}),
    ("PORT_SCAN", {"window_seconds": True}),
    ("PORT_SCAN", {"ports": 20}),
    ("PORT_SCAN", {"severity": "Huge"}),
    ("PORT_SCAN", {"enabled": "yes"}),
    ("PORT_SCAN", {"cooldown_seconds": 0}),
    ("TRAFFIC_SPIKE", {"window_minutes": 61}),
    ("ARP_SPOOFING", {"protected_bindings": {"192.168.1.1": "ff:ff:ff:ff:ff:ff"}}),
    ("ARP_SPOOFING", {"protected_bindings": "192.168.1.1"}),
    ("ARP_SPOOFING", {"protected_bindings": {"0.0.0.0": "02:00:00:00:00:01"}}),
    ("DNS_TUNNEL", {"enabled": False}),
])
def test_invalid_changes_are_refused(database, rule_code, changes):
    engine, _, _ = database
    with Session(engine) as session, pytest.raises(ValueError):
        update_rule(session, rule_code, changes)


def test_invalid_stored_settings(database):
    with pytest.raises(ValueError):
        validate_settings("DNS_TUNNEL", {})
    with pytest.raises(ValueError):
        validate_settings("PORT_SCAN", ["distinct_ports"])
    with pytest.raises(ValueError):
        TrafficSpikeSettings(severity="Huge")
    with pytest.raises(ValueError):
        validate_settings("PORT_SCAN", {"distinct_ports": 20})


def test_detection_settings_come_from_the_database(database):
    engine, _, _ = database
    with Session(engine) as session:
        settings = traffic_spike_settings(session)
        assert (settings.max_bytes_per_minute, settings.severity, settings.enabled) == (104857600, "Medium", True)
        assert arp_spoofing_settings(session)["bindings"] == {}

        update_rule(session, "TRAFFIC_SPIKE", {"max_bytes_per_minute": 500, "severity": "High", "cooldown_seconds": 60})
        update_rule(session, "ARP_SPOOFING", {"protected_bindings": ROUTER_BINDING, "severity": "Critical"})

        settings = traffic_spike_settings(session)
        assert (settings.max_bytes_per_minute, settings.severity, settings.cooldown_seconds) == (500, "High", 60)
        assert arp_spoofing_settings(session) == {
            "bindings": {"192.168.1.1": "B8:27:EB:12:34:56"},
            "severity": "Critical",
            "cooldown_seconds": 300,
            "enabled": True,
        }

        session.delete(get_rule(session, "ARP_SPOOFING"))
        session.commit()
        with pytest.raises(ValueError, match="Run the database migrations"):
            arp_spoofing_settings(session)


def test_monitoring_refuses_broken_settings(admin_api, database, monkeypatch):
    engine, _, _ = database
    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "ap0")
    with Session(engine) as session:
        get_rule(session, "TRAFFIC_SPIKE").settings_json = {"window_minutes": 0}
        session.commit()

    response = admin_api.post("/api/system/monitoring/start")
    assert response.status_code == 503
    assert response.json()["error"]["message"].startswith("Invalid detection settings")


def test_command_line_tool(database, monkeypatch, capsys):
    engine, _, _ = database
    monkeypatch.setattr(manage_rules, "get_engine", lambda: engine)

    assert manage_rules.main(["list"]) == 0
    assert "PORT_SCAN      on  Medium" in capsys.readouterr().out

    assert manage_rules.main(["set", "port_scan", "distinct_ports=25", "enabled=false"]) == 0
    output = capsys.readouterr().out
    assert "Saved." in output
    assert "PORT_SCAN      off Medium" in output

    binding = 'protected_bindings={"192.168.1.1": "b8:27:eb:12:34:56"}'
    assert manage_rules.main(["set", "ARP_SPOOFING", binding, "severity=Critical"]) == 0
    assert '"192.168.1.1": "B8:27:EB:12:34:56"' in capsys.readouterr().out

    assert manage_rules.main(["set", "PORT_SCAN", "distinct_ports=1"]) == 1
    assert "Error: distinct_ports must be between 2 and 1000." in capsys.readouterr().err

    with pytest.raises(SystemExit):
        manage_rules.main(["set", "PORT_SCAN", "distinct_ports"])