from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AuditEvent, Device, Incident


def add_incident(engine, **values):
    data = {
        "rule_code": "port_scan",
        "source_ip": "192.168.1.50",
        "target_ip": "192.168.1.10",
        "risk_score": 60,
        "severity": "High",
        "evidence_json": {"ports": 25},
    }
    data.update(values)
    with Session(engine) as session:
        incident = Incident(**data)
        session.add(incident)
        session.commit()
        return incident.id


def test_incidents_require_login(api):
    assert api.get("/api/incidents").status_code == 401
    assert api.get("/api/incidents/1").status_code == 401
    assert api.patch("/api/incidents/1", json={"status": "resolved"}).status_code == 401


def test_list_newest_first_with_filters(admin_api, database):
    engine, _, _ = database
    now = utc_now()
    old = add_incident(engine, severity="Low", created_at=now - timedelta(hours=1), updated_at=now - timedelta(hours=1))
    new = add_incident(engine, severity="Critical", risk_score=90, created_at=now, updated_at=now)

    incidents = admin_api.get("/api/incidents").json()
    assert [incident["id"] for incident in incidents] == [new, old]

    incidents = admin_api.get("/api/incidents", params={"severity": "Low"}).json()
    assert [incident["id"] for incident in incidents] == [old]

    incidents = admin_api.get("/api/incidents", params={"status": "resolved"}).json()
    assert incidents == []

    incidents = admin_api.get("/api/incidents", params={"limit": 1}).json()
    assert len(incidents) == 1


def test_list_rejects_bad_filters(admin_api):
    response = admin_api.get("/api/incidents", params={"severity": "Huge"})
    assert response.status_code == 422
    assert response.json()["error"]["fields"][0]["field"] == "query.severity"

    assert admin_api.get("/api/incidents", params={"limit": 0}).status_code == 422


def test_incident_detail(admin_api, database):
    engine, _, _ = database
    with Session(engine) as session:
        device = Device(mac_address="00:11:22:33:44:55", current_ip="192.168.1.50")
        session.add(device)
        session.commit()
        device_id = device.id
    incident_id = add_incident(engine, source_device_id=device_id)

    response = admin_api.get(f"/api/incidents/{incident_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["evidence"] == {"ports": 25}
    assert body["source_device"]["mac_address"] == "00:11:22:33:44:55"

    assert admin_api.get("/api/incidents/999").status_code == 404


def test_change_status(admin_api, database):
    engine, _, _ = database
    incident_id = add_incident(engine)

    response = admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "resolved"})
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"
    assert response.json()["resolved_at"] is not None

    admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "resolved"})

    response = admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "investigating"})
    assert response.json()["status"] == "investigating"
    assert response.json()["resolved_at"] is None

    with Session(engine) as session:
        events = session.scalars(select(AuditEvent).where(AuditEvent.event_type == "incident.status_changed")).all()
        assert [event.details_json["to"] for event in events] == ["resolved", "investigating"]
        assert all(event.incident_id == incident_id for event in events)


def test_change_status_rejects_unknown_status(admin_api, database):
    engine, _, _ = database
    incident_id = add_incident(engine)
    response = admin_api.patch(f"/api/incidents/{incident_id}", json={"status": "closed"})
    assert response.status_code == 422