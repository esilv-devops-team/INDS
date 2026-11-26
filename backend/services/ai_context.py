import ipaddress
import os
from datetime import timedelta

from sqlalchemy import func, select

from backend.database.models import Device, Incident, TrafficSummary
from backend.services.vendor_lookup import normalize_mac

TRAFFIC_MARGIN_MINUTES = 10
USUAL_TRAFFIC_HOURS = 24
NEW_DEVICE_MINUTES = 60
PREVIOUS_LIMIT = 5
HIDDEN_KEYS = ("hostname",)
TRAFFIC_FIELDS = ("bytes_sent", "bytes_received", "packets_sent", "packets_received", "connection_count")


def device_ref(device):
    return f"device-{device.id}"


def describe_address(session, value):
    if not value or value == "unknown":
        return "unknown"
    if value == "multiple":
        return "multiple targets"
    text = str(value).strip()

    try:
        mac = normalize_mac(text)
    except ValueError:
        mac = None
    if mac is not None:
        if mac == os.environ.get("INDS_MONITOR_AP_MAC", "").strip().upper():
            return "access point"
        device = session.scalar(select(Device).where(Device.mac_address == mac))
        return device_ref(device) if device is not None else "unknown device"

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    device = session.scalar(select(Device).where(Device.current_ip == text).limit(1))
    if device is not None:
        return device_ref(device)
    return "lan host" if address.is_private else "external host"


def clean_evidence(session, evidence):
    cleaned = {}
    for key, value in evidence.items():
        if key.endswith(("_ip", "_mac")):
            cleaned[key.rsplit("_", 1)[0]] = describe_address(session, value)
        elif key not in HIDDEN_KEYS:
            cleaned[key] = value
    return cleaned


def traffic_between(session, device_id, start, end):
    row = session.execute(
        select(func.count(TrafficSummary.id), *[func.coalesce(func.sum(getattr(TrafficSummary, field)), 0) for field in TRAFFIC_FIELDS])
        .where(TrafficSummary.device_id == device_id, TrafficSummary.window_start >= start, TrafficSummary.window_start <= end)
    ).one()
    return row[0], dict(zip(TRAFFIC_FIELDS, row[1:]))


def traffic_stats(session, incident):
    if incident.source_device_id is None:
        return None
    start = incident.first_seen_at - timedelta(minutes=TRAFFIC_MARGIN_MINUTES)
    minutes, during = traffic_between(session, incident.source_device_id, start, incident.last_seen_at)
    usual_minutes, usual = traffic_between(
        session, incident.source_device_id, start - timedelta(hours=USUAL_TRAFFIC_HOURS), start - timedelta(seconds=1)
    )
    return {
        "minutes_measured": minutes,
        "during_incident": during,
        "usual_per_minute": {field: round(total / usual_minutes) for field, total in usual.items()} if usual_minutes else None,
    }


def device_info(session, incident):
    device = incident.source_device
    if device is None:
        return None
    known_for = incident.first_seen_at - device.first_seen_at
    other_open = session.scalar(
        select(func.count(Incident.id)).where(
            Incident.source_device_id == device.id, Incident.status != "resolved", Incident.id != incident.id
        )
    )
    return {
        "ref": device_ref(device),
        "vendor": device.vendor or "Unknown",
        "trusted": device.is_trusted,
        "first_seen_at": device.first_seen_at.isoformat(),
        "minutes_known_before_incident": max(int(known_for.total_seconds() // 60), 0),
        "new_device": known_for < timedelta(minutes=NEW_DEVICE_MINUTES),
        "other_open_incidents": other_open,
    }


def previous_incidents(session, incident):
    if incident.source_device_id is None:
        return []
    older = session.scalars(
        select(Incident)
        .where(Incident.source_device_id == incident.source_device_id, Incident.id < incident.id)
        .order_by(Incident.first_seen_at.desc(), Incident.id.desc())
        .limit(PREVIOUS_LIMIT)
    )
    return [
        {
            "threat_type": old.rule_code,
            "severity": old.severity,
            "risk_score": old.risk_score,
            "status": old.status,
            "occurrences": old.evidence_json.get("occurrences", 1),
            "first_seen_at": old.first_seen_at.isoformat(),
        }
        for old in older
    ]


def build_context(session, incident):
    if incident.source_device is not None:
        source = device_ref(incident.source_device)
    else:
        source = describe_address(session, incident.source_ip)
    return {
        "incident_id": incident.id,
        "threat_type": incident.rule_code,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "occurrences": incident.evidence_json.get("occurrences", 1),
        "first_seen_at": incident.first_seen_at.isoformat(),
        "last_seen_at": incident.last_seen_at.isoformat(),
        "source": source,
        "target": describe_address(session, incident.target_ip),
        "evidence": clean_evidence(session, incident.evidence_json),
        "device": device_info(session, incident),
        "traffic": traffic_stats(session, incident),
        "previous_incidents": previous_incidents(session, incident),
    }
