from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Device, Incident, MonitoringRun, ResponseAction
from backend.services import deepseek
from backend.services.ai_analysis import process_next, queue_analysis

NOW = utc_now().replace(microsecond=0)
MAC = "02:00:00:00:00:66"
ADDRESS = "192.168.50.66"
SCORES = {"Medium": 40, "High": 65, "Critical": 85}


def answer(**changes):
    result = {
        "summary": "device-1 scans the camera.",
        "classification": "Port scan",
        "explanation": "device-1 tried 25 ports on the camera in one minute.",
        "risk_level": "Critical",
        "evidence": ["25 distinct ports in 60 seconds"],
        "impact": "Open services on the camera can be found.",
        "recommended_action": "block",
        "justification": "The scan is still going on and the device is not trusted.",
        "confidence": 90,
        "uncertainty": "It could be a network tool used by the owner.",
    }
    result.update(changes)
    return result


def detect(engine, severity="High", trusted=False, ip_source="dhcp_lease", status="open"):
    with Session(engine) as session, session.begin():
        admin = Administrator(username="setup", password_hash="x")
        session.add(admin)
        session.flush()
        run = MonitoringRun(started_by_id=admin.id, started_at=NOW - timedelta(hours=1))
        device = Device(mac_address=MAC, current_ip=ADDRESS, ip_source=ip_source, is_trusted=trusted,
                        first_seen_at=NOW - timedelta(days=1), last_seen_at=NOW)
        incident = Incident(
            source_device=device, monitoring_run=run, rule_code="PORT_SCAN", source_ip=ADDRESS,
            target_ip="192.168.50.20", severity=severity, risk_score=SCORES[severity], status=status,
            resolved_at=NOW + timedelta(days=1) if status == "resolved" else None,
            first_seen_at=NOW, last_seen_at=NOW, evidence_json={"distinct_ports": 25, "occurrences": 1},
        )
        session.add_all([run, incident])
        session.flush()
        queue_analysis(session, incident)
        return incident.id


def analyse(engine, monkeypatch, reply):
    monkeypatch.setattr(deepseek, "ask_deepseek", lambda context: reply)
    assert process_next(engine)
    with Session(engine) as session:
        analysis = session.scalar(select(AIAnalysis).order_by(AIAnalysis.id.desc()))
        actions = session.scalars(select(ResponseAction)).all()
        session.expunge_all()
        return analysis, actions


def test_block_recommendation_creates_proposal(database, monkeypatch):
    engine, _, _ = database
    incident_id = detect(engine)
    analysis, actions = analyse(engine, monkeypatch, answer())

    action, = actions
    assert (action.incident_id, action.ai_analysis_id, action.action_type) == (incident_id, analysis.id, "block")
    assert (action.target_mac, action.target_ip) == (MAC, ADDRESS)
    assert (action.approval_status, action.execution_status) == ("pending", "not_applied")
    assert action.requested_by_id is None
    assert action.expires_at is None
    assert action.reason == "AI: The scan is still going on and the device is not trusted."
    assert analysis.assessment_json["recommended_action"] == "block"
    assert analysis.assessment_json["response_note"] == "Block proposed, waiting for the administrator."

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "response_action.proposed"))
        assert (event.actor_type, event.response_action_id) == ("system", action.id)
        incident = session.get(Incident, incident_id)
        assert (incident.severity, incident.risk_score) == ("High", 65)


def test_critical_incident_gets_temporary_block(database, monkeypatch):
    engine, _, _ = database
    detect(engine, severity="Critical")
    analysis, (action,) = analyse(engine, monkeypatch, answer())
    assert 14 * 60 <= (action.expires_at - action.created_at).total_seconds() <= 15 * 60
    assert analysis.assessment_json["response_note"] == "Temporary block (15 min) proposed, waiting for the administrator."


@pytest.mark.parametrize("changes, situation, saved_action, note", [
    ({"recommended_action": "monitor"}, {}, "monitor", "No action proposed, INDS keeps monitoring the device."),
    ({"recommended_action": "quarantine"}, {}, "monitor", 'INDS does not support "quarantine", it was saved as monitor.'),
    ({}, {"severity": "Medium"}, "block",
     "Block not proposed: the policy only blocks High or Critical incidents (this one is Medium)."),
    ({}, {"trusted": True}, "block", "Block not proposed: Device is protected or protection settings are invalid."),
    ({}, {"ip_source": None}, "block", "Block not proposed: Current LAN address ownership is unconfirmed."),
    ({}, {"status": "resolved"}, "block", "Block not proposed: the incident is already resolved."),
])
def test_no_proposal(database, monkeypatch, changes, situation, saved_action, note):
    engine, _, _ = database
    detect(engine, **situation)
    analysis, actions = analyse(engine, monkeypatch, answer(**changes))
    assert actions == []
    assert analysis.status == "succeeded"
    assert analysis.assessment_json["recommended_action"] == saved_action
    assert analysis.assessment_json["response_note"] == note


def test_policy_switch_off(database, monkeypatch):
    engine, _, _ = database
    monkeypatch.setenv("INDS_ALLOW_BLOCK_PROPOSALS", "0")
    detect(engine)
    analysis, actions = analyse(engine, monkeypatch, answer())
    assert actions == []
    assert analysis.assessment_json["response_note"] == "Block not proposed: Block proposals are disabled by policy."


def test_no_duplicate_proposal(database, monkeypatch):
    engine, _, _ = database
    incident_id = detect(engine)
    with Session(engine) as session, session.begin():
        session.add(ResponseAction(incident_id=incident_id, action_type="block", target_mac=MAC,
                                   request_key="manual", reason="Blocked by hand"))
    analysis, actions = analyse(engine, monkeypatch, answer())
    assert len(actions) == 1
    assert analysis.assessment_json["response_note"] == "Block not proposed: a block for this device is already pending or active."


def test_administrator_decides(admin_api, database, monkeypatch):
    engine, _, _ = database
    incident_id = detect(engine)
    _, (action,) = analyse(engine, monkeypatch, answer())

    detail = admin_api.get(f"/api/incidents/{incident_id}").json()
    assert detail["actions"][0]["id"] == action.id
    assert detail["analyses"][0]["assessment"]["recommended_action"] == "block"

    approved = admin_api.post(f"/api/actions/{action.id}/decision", json={"decision": "approved"})
    assert approved.status_code == 200
    assert (approved.json()["approval_status"], approved.json()["execution_status"]) == ("approved", "not_applied")


def test_administrator_rejects(admin_api, database, monkeypatch):
    engine, _, _ = database
    detect(engine)
    _, (action,) = analyse(engine, monkeypatch, answer())
    rejected = admin_api.post(f"/api/actions/{action.id}/decision", json={"decision": "rejected"})
    assert rejected.status_code == 200
    assert rejected.json()["approval_status"] == "rejected"
