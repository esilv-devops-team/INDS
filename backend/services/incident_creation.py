from datetime import UTC, timedelta

from sqlalchemy import select

from backend.database.models import Device, Incident, MonitoringRun
from backend.services.ai_analysis import queue_analysis
from backend.services.audit import record_event
from backend.services.severity import classify_severity

CORRELATION_MINUTES = 10
NEW_DEVICE_MINUTES = 60
BASE_SCORES = {"Low": 20, "Medium": 40, "High": 65, "Critical": 85}
REPEAT_BONUS = 5
MAX_REPEAT_BONUS = 15
NEW_DEVICE_BONUS = 10


def to_utc(moment):
    if moment.tzinfo is None:
        return moment
    return moment.astimezone(UTC).replace(tzinfo=None)


def find_device(session, finding):
    if finding.source_device_id is not None:
        device = session.get(Device, finding.source_device_id)
        if device is not None:
            return device
    if finding.source_mac:
        return session.scalar(select(Device).where(Device.mac_address == finding.source_mac.upper()))
    return None


def risk_score(rule_severity, occurrences, device, first_seen):
    score = BASE_SCORES[rule_severity] + min(REPEAT_BONUS * (occurrences - 1), MAX_REPEAT_BONUS)
    if device is not None and first_seen - device.first_seen_at < timedelta(minutes=NEW_DEVICE_MINUTES):
        score += NEW_DEVICE_BONUS
    return min(score, 100)


def evidence_for(finding, occurrences):
    return {**finding.evidence, **finding.measured, "rule_severity": finding.severity, "occurrences": occurrences}


def record_finding(session, run_id, finding):
    device = find_device(session, finding)
    seen_at = to_utc(finding.timestamp)
    device_ip = device.current_ip if device is not None and device.current_ip else "unknown"
    source_ip = finding.evidence.get("source_ip", device_ip)
    target_ip = finding.evidence.get("target_ip") or finding.evidence.get("sender_ip") or "multiple"
    trusted = device is not None and device.is_trusted

    query = select(Incident).where(
        Incident.rule_code == finding.rule_id,
        Incident.status != "resolved",
        Incident.source_ip == source_ip,
        Incident.target_ip == target_ip,
        Incident.last_seen_at >= seen_at - timedelta(minutes=CORRELATION_MINUTES),
    )
    if device is not None:
        query = query.where(Incident.source_device_id == device.id)
    else:
        query = query.where(Incident.source_device_id.is_(None))
    incident = session.scalar(query.order_by(Incident.last_seen_at.desc()).limit(1))

    if incident is not None:
        occurrences = incident.evidence_json.get("occurrences", 1) + 1
        old_severity = incident.severity
        score = risk_score(finding.severity, occurrences, device, incident.first_seen_at)
        incident.last_seen_at = max(incident.last_seen_at, seen_at)
        incident.evidence_json = evidence_for(finding, occurrences)
        incident.risk_score = max(incident.risk_score or 0, score)
        incident.severity = classify_severity(incident.risk_score, trusted)
        if incident.severity != old_severity:
            record_event(
                session, "incident.escalated", incident_id=incident.id, device_id=incident.source_device_id,
                details={"from": old_severity, "to": incident.severity, "risk_score": incident.risk_score},
            )
        return incident, False

    score = risk_score(finding.severity, 1, device, seen_at)
    incident = Incident(
        source_device_id=device.id if device is not None else None,
        monitoring_run_id=run_id,
        rule_code=finding.rule_id,
        source_ip=source_ip,
        target_ip=target_ip,
        first_seen_at=seen_at,
        last_seen_at=seen_at,
        risk_score=score,
        severity=classify_severity(score, trusted),
        evidence_json=evidence_for(finding, 1),
    )
    session.add(incident)
    session.flush()
    queue_analysis(session, incident)
    record_event(
        session, "incident.created", incident_id=incident.id, device_id=incident.source_device_id,
        monitoring_run_id=run_id,
        details={"rule": finding.rule_id, "severity": incident.severity, "risk_score": score},
    )
    return incident, True


def record_findings(session, run_id, findings):
    run = session.get(MonitoringRun, run_id)
    if run is None or run.ended_at is not None:
        return []
    return [record_finding(session, run_id, finding) for finding in findings]
