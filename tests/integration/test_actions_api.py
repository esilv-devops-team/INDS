from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Device, Incident, MonitoringRun, ResponseAction


def add_incident_with_response(engine):
    now = utc_now()
    with Session(engine) as session:
        incident = Incident(rule_code="arp_spoof", source_ip="192.168.1.21", target_ip="192.168.1.1", severity="Critical", risk_score=88)
        session.add(incident)
        session.flush()

        analysis = AIAnalysis(
            incident_id=incident.id,
            model="deepseek-chat",
            prompt_version="v1",
            status="succeeded",
            input_summary_json={"rule": "arp_spoof"},
            assessment_json={"summary": "Device pretends to be the router", "recommendation": "block"},
            requested_at=now,
            started_at=now,
            completed_at=now + timedelta(seconds=4),
        )
        session.add(analysis)
        session.add(AIAnalysis(
            incident_id=incident.id,
            model="deepseek-chat",
            prompt_version="v1",
            status="failed",
            input_summary_json={"rule": "arp_spoof"},
            error_message="timeout",
            requested_at=now - timedelta(minutes=1),
            started_at=now - timedelta(minutes=1),
            completed_at=now - timedelta(seconds=30),
        ))
        session.flush()

        action = ResponseAction(
            incident_id=incident.id,
            ai_analysis_id=analysis.id,
            request_key="incident-1-block",
            action_type="block",
            target_mac="da:a1:19:5c:0e:42",
            target_ip="192.168.1.21",
            reason="ARP spoofing against the router",
        )
        session.add(action)
        session.commit()
        return incident.id, action.id


def start_monitoring(admin_api, engine):
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    with Session(engine) as session:
        session.add(MonitoringRun(started_by_id=admin_id))
        session.commit()


def test_detail_shows_analyses_and_actions(admin_api, database):
    engine, _, _ = database
    incident_id, action_id = add_incident_with_response(engine)

    body = admin_api.get(f"/api/incidents/{incident_id}").json()
    assert [analysis["status"] for analysis in body["analyses"]] == ["succeeded", "failed"]
    assert body["analyses"][0]["assessment"]["summary"] == "Device pretends to be the router"
    assert body["analyses"][1]["error_message"] == "timeout"
    assert body["actions"][0]["id"] == action_id
    assert body["actions"][0]["target_mac"] == "DA:A1:19:5C:0E:42"
    assert body["actions"][0]["approval_status"] == "pending"
    assert body["actions"][0]["decided_by"] is None


def test_decision_requires_login(api):
    assert api.post("/api/actions/1/decision", json={"decision": "approved"}).status_code == 401


def test_response_history_requires_login(api):
    assert api.get("/api/actions").status_code == 401


def test_response_history_filters_and_keeps_execution_separate(admin_api, database):
    engine, _, _ = database
    incident_id, pending_id = add_incident_with_response(engine)
    created = utc_now()
    with Session(engine) as session, session.begin():
        admin = session.scalar(select(Administrator))
        device = Device(mac_address="DA:A1:19:5C:0E:42")
        session.add(device)
        session.flush()
        device_id = device.id
        session.get(ResponseAction, pending_id).device = device

        for execution in ("not_applied", "active"):
            confirmed = execution == "active"
            session.add(ResponseAction(
                incident_id=incident_id, device=device,
                request_key=f"history-{execution}", action_type="block",
                target_mac=device.mac_address, reason="Repeated reports",
                approval_status="approved", execution_status=execution,
                decided_by=admin, created_at=created, decided_at=created,
                applied_at=created if confirmed else None,
            ))

    approved = admin_api.get(f"/api/actions?device_id={device_id}&approval=approved").json()
    assert [action["execution_status"] for action in approved] == ["active", "not_applied"]
    assert approved[0]["applied_at"] == created.isoformat()
    assert approved[0]["decided_by"]["username"] == "admin"
    assert approved[1]["applied_at"] is None
    assert admin_api.get("/api/actions?execution=active").json() == approved[:1]
    assert admin_api.get("/api/actions?approval=approved&limit=1&offset=1").json() == approved[1:]
    assert admin_api.get("/api/actions?device_id=9999").json() == []
    assert admin_api.get("/api/actions?execution=unsupported").status_code == 422


def test_approve_needs_monitoring_on(admin_api, database):
    engine, _, _ = database
    _, action_id = add_incident_with_response(engine)

    response = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"})
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "turn monitoring on before approving a response"


def test_approve(admin_api, database):
    engine, _, _ = database
    incident_id, action_id = add_incident_with_response(engine)
    start_monitoring(admin_api, engine)

    response = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"})
    assert response.status_code == 200
    body = response.json()
    assert body["approval_status"] == "approved"
    assert body["decided_by"] == {"username": "admin"}
    assert body["decided_at"] is not None
    assert body["execution_status"] == "not_applied"

    response = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "rejected"})
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "this action is already approved"

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "response_action.approved"))
        assert event.response_action_id == action_id
        assert event.incident_id == incident_id
        assert event.details_json == {"action_type": "block", "target_mac": "DA:A1:19:5C:0E:42"}


def test_reject_works_when_monitoring_is_off(admin_api, database):
    engine, _, _ = database
    incident_id, action_id = add_incident_with_response(engine)

    response = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "rejected"})
    assert response.status_code == 200
    assert response.json()["approval_status"] == "rejected"

    actions = admin_api.get(f"/api/incidents/{incident_id}").json()["actions"]
    assert actions[0]["decided_by"]["username"] == "admin"

    with Session(engine) as session:
        action = session.get(ResponseAction, action_id)
        assert action.decided_by_id is not None


def test_decision_errors(admin_api):
    assert admin_api.post("/api/actions/999/decision", json={"decision": "approved"}).status_code == 404
    assert admin_api.post("/api/actions/1/decision", json={"decision": "maybe"}).status_code == 422
