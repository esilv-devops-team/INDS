from sqlalchemy import select

from backend.database.models import DetectionRule
from backend.services.arp_detection import parse_bindings
from backend.services.audit import record_event
from detection.rules.port_scan import PortScanSettings
from detection.rules.traffic_spike import TrafficSpikeSettings

SEVERITIES = ("Low", "Medium", "High", "Critical")

LIMITS = {
    "TRAFFIC_SPIKE": {"window_minutes": (1, 60), "max_bytes_per_minute": (1, 10**12), "max_packets_per_minute": (1, 10**9)},
    "PORT_SCAN": {"distinct_ports": (2, 1000), "window_seconds": (5, 3600)},
    "ARP_SPOOFING": {},
}


def check_number(name, value, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a whole number.")
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}.")
    return value


def validate_settings(rule_code, settings):
    if rule_code not in LIMITS:
        raise ValueError(f"Unknown detection rule {rule_code}.")
    if not isinstance(settings, dict):
        raise ValueError("Rule settings must be an object.")

    expected = set(LIMITS[rule_code])
    if rule_code == "ARP_SPOOFING":
        expected = {"protected_bindings"}
    if set(settings) != expected:
        raise ValueError(f"{rule_code} settings must contain exactly: {', '.join(sorted(expected))}.")

    if rule_code == "ARP_SPOOFING":
        return {"protected_bindings": parse_bindings(settings["protected_bindings"])}
    return {name: check_number(name, settings[name], *limits) for name, limits in LIMITS[rule_code].items()}


def get_rule(session, rule_code):
    rule = session.scalar(select(DetectionRule).where(DetectionRule.rule_code == rule_code))
    if rule is None:
        raise ValueError(f"Detection rule {rule_code} is missing. Run the database migrations.")
    return rule


def list_rules(session):
    return session.scalars(select(DetectionRule).order_by(DetectionRule.rule_code)).all()


def update_rule(session, rule_code, changes, admin=None):
    rule = get_rule(session, rule_code)
    old = {"enabled": rule.enabled, "severity": rule.severity,
           "cooldown_seconds": rule.cooldown_seconds, "settings": rule.settings_json}
    new = dict(old)

    for key, value in changes.items():
        if key == "enabled":
            if not isinstance(value, bool):
                raise ValueError("enabled must be true or false.")
            new["enabled"] = value
        elif key == "severity":
            if value not in SEVERITIES:
                raise ValueError("severity must be Low, Medium, High or Critical.")
            new["severity"] = value
        elif key == "cooldown_seconds":
            new["cooldown_seconds"] = check_number("cooldown_seconds", value, 1, 86400)
        elif key in rule.settings_json:
            new["settings"] = {**new["settings"], key: value}
        else:
            raise ValueError(f"Unknown setting {key} for {rule_code}.")

    new["settings"] = validate_settings(rule_code, new["settings"])
    if new == old:
        return rule

    rule.enabled = new["enabled"]
    rule.severity = new["severity"]
    rule.cooldown_seconds = new["cooldown_seconds"]
    rule.settings_json = new["settings"]
    changed = {key: new[key] for key in new if new[key] != old[key]}
    record_event(session, "detection_rule.updated", admin=admin, details={"rule": rule_code, "changes": changed})
    session.commit()
    return rule


def traffic_spike_settings(session):
    rule = get_rule(session, "TRAFFIC_SPIKE")
    settings = validate_settings(rule.rule_code, rule.settings_json)
    return TrafficSpikeSettings(
        enabled=rule.enabled, severity=rule.severity, cooldown_seconds=rule.cooldown_seconds, **settings,
    )


def arp_spoofing_settings(session):
    rule = get_rule(session, "ARP_SPOOFING")
    settings = validate_settings(rule.rule_code, rule.settings_json)
    return {
        "bindings": settings["protected_bindings"],
        "severity": rule.severity,
        "cooldown_seconds": rule.cooldown_seconds,
        "enabled": rule.enabled,
    }


def port_scan_settings(session):
    rule = get_rule(session, "PORT_SCAN")
    settings = validate_settings(rule.rule_code, rule.settings_json)
    return PortScanSettings(
        enabled=rule.enabled, severity=rule.severity, cooldown_seconds=rule.cooldown_seconds, **settings,
    )