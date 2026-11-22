from datetime import UTC, timedelta

from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, Incident, MonitoringRun, ResponseAction
from backend.services.incident_creation import attach_ai_assessment, record_findings
from detection.base import Finding

NOW = utc_now().replace(microsecond=0)


def add_incident(engine, **values):
    data = {
        "rule_code": "PORT_SCAN",
        "source_ip": "192.168.50.66",
        "target_ip": "192.168.50.20",
        "risk_score": 40,
        "severity": "Medium",
        "evidence_json": {"distinct_ports": 20},
    }
    data.update(values)
    with Session(engine) as session:
        incident = Incident(**data)
        session.add(incident)
        session.commit()
        return incident.id


def detect_scan(admin_api, engine, repeats):
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    with Session(engine) as session, session.begin():
        run = MonitoringRun(started_by_id=admin_id, started_at=NOW - timedelta(hours=1))
        device = Device(mac_address="02:00:00:00:00:66", current_ip="192.168.50.66",
                        first_seen_at=NOW - timedelta(days=1), last_seen_at=NOW)
        session.add_all([run, device])
        session.flush()
        findings = [
            Finding("PORT_SCAN", device.id, (NOW + timedelta(minutes=minute)).replace(tzinfo=UTC), "Medium",
                    {"source_ip": "192.168.50.66", "target_ip": "192.168.50.20"}, {"distinct_ports": 20})
            for minute in range(repeats)
        ]
        incident, _ = record_findings(session, run.id, findings)[0]
        return incident.id, device.id


def test_history_requires_login(api):
    assert api.get("/api/incidents/1/history").status_code == 401
    assert api.get("/api/incidents/counts").status_code == 401


def test_history_tells_the_whole_story(admin_api, database):
    engine, _, _ = database
    incident_id, device_id = detect_scan(admin_api, engine, repeats=5)

    with Session(engine) as session, session.begin():
        attach_ai_assessment(session, session.get(Incident, incident_id), "llama3", {"summary": "A guest scans the camera."})
        session.add(ResponseAction(
            incident_id=incident_id, device_id=device_id, request_key="history-block", action_type="block",
            target_mac="02:00:00:00:00:66", reason="Port scan against the camera",
        ))
    action_id = admin_api.get(f"/api/incidents/{incident_id}").json()["actions"][0]["id"]
    assert admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "rejected"}).status_code == 200
    admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "investigating"})
    admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "resolved", "note": "  The camera was updated.  "})

    response = admin_api.get(f"/api/incidents/{incident_id}/history")
    assert response.status_code == 200
    events = response.json()
    assert [event["event_type"] for event in events] == [
        "incident.created",
        "incident.escalated",
        "ai_analysis.attached",
        "response_action.rejected",
        "incident.status_changed",
        "incident.status_changed",
    ]
    assert [event["actor"] for event in events] == [None, None, None, "admin", "admin", "admin"]
    assert events[0]["details"] == {"rule": "PORT_SCAN", "severity": "Medium", "risk_score": 40}
    assert events[1]["details"] == {"from": "Medium", "to": "High", "risk_score": 55}
    assert events[3]["response_action_id"] == action_id
    assert events[4]["details"] == {"from": "open", "to": "investigating"}
    assert events[5]["details"] == {"from": "investigating", "to": "resolved", "note": "The camera was updated."}
    times = [event["occurred_at"] for event in events]
    assert times == sorted(times)


def test_history_of_other_incidents_stays_separate(admin_api, database):
    engine, _, _ = database
    first = add_incident(engine)
    second = add_incident(engine)
    admin_api.patch(f"/api/incidents/{first}", json={"status": "resolved", "note": "   "})

    events = admin_api.get(f"/api/incidents/{first}/history").json()
    assert len(events) == 1
    assert events[0]["details"] == {"from": "open", "to": "resolved"}
    assert admin_api.get(f"/api/incidents/{second}/history").json() == []
    assert admin_api.get("/api/incidents/999/history").status_code == 404


def test_note_is_limited(admin_api, database):
    engine, _, _ = database
    incident_id = add_incident(engine)
    response = admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "resolved", "note": "x" * 301})
    assert response.status_code == 422
    assert admin_api.get(f"/api/incidents/{incident_id}").json()["status"] == "open"


def test_old_incidents_stay_reachable(admin_api, database):
    engine, _, _ = database
    ids = [
        add_incident(engine, status="resolved", resolved_at=NOW - timedelta(days=day),
                     created_at=NOW - timedelta(days=day + 1), updated_at=NOW - timedelta(days=day))
        for day in range(30, 0, -1)
    ]
    active = add_incident(engine, rule_code="ARP_SPOOFING", target_ip="192.168.50.1", status="investigating")
    open_one = add_incident(engine, rule_code="TRAFFIC_SPIKE", source_ip="192.168.50.80", target_ip="multiple")

    def listed(**params):
        return [incident["id"] for incident in admin_api.get("/api/incidents", params=params).json()]

    assert listed(status="active") == [open_one, active]
    assert listed(status="resolved", limit=10) == ids[::-1][:10]
    assert listed(status="resolved", limit=10, offset=25) == ids[::-1][25:]
    assert listed(search="port scan") == ids[::-1]
    assert listed(search="arp", status="active") == [active]
    assert listed(search=".80") == [open_one]
    assert listed(search="  ", limit=500) == [open_one, active] + ids[::-1]
    assert admin_api.get("/api/incidents", params={"limit": 501}).status_code == 422
    assert admin_api.get("/api/incidents", params={"search": "x" * 51}).status_code == 422
    assert admin_api.get("/api/incidents", params={"status": "closed"}).status_code == 422

    assert admin_api.get("/api/incidents/counts").json() == {"open": 1, "investigating": 1, "resolved": 30}


def test_counts_without_incidents(admin_api):
    assert admin_api.get("/api/incidents/counts").json() == {"open": 0, "investigating": 0, "resolved": 0}