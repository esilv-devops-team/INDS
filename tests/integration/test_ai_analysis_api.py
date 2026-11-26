from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, AuditEvent, Device, Incident, MonitoringRun
from backend.services import deepseek
from backend.services.ai_analysis import process_next

NOW = utc_now().replace(microsecond=0)


def add_incident(admin_api, engine, ended=False, analysis_status=None, mac="02:00:00:00:00:66"):
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    with Session(engine) as session, session.begin():
        run = MonitoringRun(started_by_id=admin_id, started_at=NOW - timedelta(hours=1))
        if ended:
            run.ended_at, run.stop_reason = NOW, "shutdown"
        device = Device(mac_address=mac, current_ip="192.168.50.66", ip_source="dhcp_lease",
                        first_seen_at=NOW - timedelta(days=1), last_seen_at=NOW)
        incident = Incident(source_device=device, monitoring_run=run, rule_code="PORT_SCAN", source_ip="192.168.50.66",
                            target_ip="192.168.50.20", severity="High", risk_score=65,
                            first_seen_at=NOW, last_seen_at=NOW, evidence_json={"distinct_ports": 25})
        session.add_all([run, incident])
        session.flush()
        if analysis_status:
            session.add(AIAnalysis(
                incident_id=incident.id, model="deepseek-flash", prompt_version="v1", status=analysis_status,
                input_summary_json={}, requested_at=NOW, started_at=NOW if analysis_status != "pending" else None,
                completed_at=NOW if analysis_status in ("failed", "succeeded") else None,
                error_message="DeepSeek did not answer in time." if analysis_status == "failed" else None,
                assessment_json={"summary": "ok"} if analysis_status == "succeeded" else None,
            ))
        return incident.id


def test_request_analysis_requires_login(api):
    assert api.post("/api/incidents/1/analysis").status_code == 401


def test_request_first_analysis(admin_api, database):
    engine, _, _ = database
    incident_id = add_incident(admin_api, engine)

    response = admin_api.post(f"/api/incidents/{incident_id}/analysis")
    assert response.status_code == 202
    assert (response.json()["status"], response.json()["model"]) == ("pending", "deepseek-flash")
    assert response.json()["started_at"] is None

    again = admin_api.post(f"/api/incidents/{incident_id}/analysis")
    assert (again.status_code, again.json()["error"]["message"]) == (409, "The AI is already analysing this incident.")

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "ai_analysis.requested"))
        assert (event.administrator.username, event.incident_id) == ("admin", incident_id)
    history = admin_api.get(f"/api/incidents/{incident_id}/history").json()
    assert [event["event_type"] for event in history] == ["ai_analysis.requested"]


def test_retry_after_failure(admin_api, database):
    engine, _, _ = database
    incident_id = add_incident(admin_api, engine, analysis_status="failed")
    assert admin_api.post(f"/api/incidents/{incident_id}/analysis").status_code == 202
    statuses = [analysis["status"] for analysis in admin_api.get(f"/api/incidents/{incident_id}").json()["analyses"]]
    assert sorted(statuses) == ["failed", "pending"]


def test_refused_requests(admin_api, database):
    engine, _, _ = database
    done = add_incident(admin_api, engine, analysis_status="succeeded")
    response = admin_api.post(f"/api/incidents/{done}/analysis")
    assert (response.status_code, response.json()["error"]["message"]) == (409, "This incident already has an AI analysis.")

    stopped = add_incident(admin_api, engine, ended=True, mac="02:00:00:00:00:67")
    response = admin_api.post(f"/api/incidents/{stopped}/analysis")
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "The monitoring run of this incident was stopped, it cannot be analysed anymore."
    assert admin_api.post("/api/incidents/999/analysis").status_code == 404


def test_detail_links_the_proposal_to_the_analysis(admin_api, database, monkeypatch):
    engine, _, _ = database
    incident_id = add_incident(admin_api, engine)
    admin_api.post(f"/api/incidents/{incident_id}/analysis")
    monkeypatch.setattr(deepseek, "ask_deepseek", lambda context: {
        "summary": "device-1 scans device-2.", "risk_level": "High", "recommended_action": "block",
        "justification": "The scan is still going on.",
    })
    assert process_next(engine)

    detail = admin_api.get(f"/api/incidents/{incident_id}").json()
    analysis = detail["analyses"][0]
    action, = detail["actions"]
    assert analysis["status"] == "succeeded"
    assert analysis["started_at"] is not None
    assert action["ai_analysis_id"] == analysis["id"]
    assert analysis["assessment"]["response_note"] == "Block proposed, waiting for the administrator."
