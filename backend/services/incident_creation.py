from datetime import UTC, timedelta

from sqlalchemy import select

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Device, Incident, MonitoringRun
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
        if device is not None and (not finding.source_mac or device.mac_address == finding.source_mac.upper()):
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
    device_ip = (device.reported_ip if device is not None else None) or "unknown"
    source_ip = finding.evidence.get("source_ip", device_ip)
    target_ip = finding.evidence.get("target_ip") or finding.evidence.get("sender_ip") or "multiple"
    trusted = device is not None and device.is_trusted

    query = select(Incident).where(
        Incident.rule_code == finding.rule_id,
        Incident.monitoring_run_id == run_id,
        Incident.status != "resolved",
        Incident.source_ip == source_ip,
        Incident.target_ip == target_ip,
        Incident.last_seen_at >= seen_at - timedelta(minutes=CORRELATION_MINUTES),
        Incident.last_seen_at <= seen_at + timedelta(minutes=CORRELATION_MINUTES),
    )
    if device is not None:
        query = query.where(Incident.source_device_id == device.id)
    elif finding.source_mac:
        query = query.where(Incident.source_device_id.is_(None),
                            Incident.evidence_json["observed_source_mac"].as_string() == finding.source_mac.upper())
    incident = (
        session.scalar(query.order_by(Incident.last_seen_at.desc()).limit(1))
        if device is not None or finding.source_mac else None
    )

    if incident is not None:
        occurrences = incident.evidence_json.get("occurrences", 1) + 1
        repeat_evidence = evidence_for(finding, occurrences)
        old_severity = incident.severity
        score = risk_score(finding.severity, occurrences, device, incident.first_seen_at)
        evidence = {**incident.evidence_json, "occurrences": occurrences}
        if seen_at >= incident.last_seen_at:
            evidence["latest_finding"] = repeat_evidence
            incident.last_seen_at = seen_at
        incident.evidence_json = evidence
        incident.risk_score = max(incident.risk_score or 0, score)
        incident.severity = classify_severity(incident.risk_score, trusted)
        record_event(session, "incident.finding_correlated", incident_id=incident.id,
                     device_id=incident.source_device_id, monitoring_run_id=run_id,
                     details={"observed_at": seen_at.isoformat(), "evidence": repeat_evidence})
        if incident.severity != old_severity:
            record_event(
                session, "incident.escalated", incident_id=incident.id, device_id=incident.source_device_id,
                details={"from": old_severity, "to": incident.severity, "risk_score": incident.risk_score},
            )
        return incident, False

    score = risk_score(finding.severity, 1, device, seen_at)
    evidence = evidence_for(finding, 1)
    if device is None and finding.source_mac:
        evidence["observed_source_mac"] = finding.source_mac.upper()
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
        evidence_json=evidence,
    )
    session.add(incident)
    session.flush()
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


def incident_summary(incident):
    evidence = {
        key: value for key, value in incident.evidence_json.items()
        if key != "latest_finding" and not key.endswith(("_ip", "_mac"))
    }
    return {
        "incident_id": incident.id,
        "rule": incident.rule_code,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "source_device": f"device-{incident.source_device_id}" if incident.source_device_id else "unknown device",
        "first_seen_at": incident.first_seen_at.isoformat(),
        "last_seen_at": incident.last_seen_at.isoformat(),
        "evidence": evidence,
    }


def attach_ai_assessment(session, incident, model, assessment, prompt_version="v1"):
    if not isinstance(assessment, dict) or not isinstance(assessment.get("summary"), str) or not assessment["summary"].strip():
        raise ValueError("An AI assessment must be an object with a non-empty summary.")
    if not model or not model.strip():
        raise ValueError("The AI model name is required.")

    now = utc_now()
    analysis = AIAnalysis(
        incident_id=incident.id,
        model=model.strip(),
        prompt_version=prompt_version,
        status="succeeded",
        input_summary_json=incident_summary(incident),
        assessment_json=assessment,
        requested_at=now,
        started_at=now,
        completed_at=now,
    )
    session.add(analysis)
    session.flush()
    record_event(
        session, "ai_analysis.attached", incident_id=incident.id, ai_analysis_id=analysis.id,
        details={"model": analysis.model},
    )
    return analysis
