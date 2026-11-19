from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import AuditEvent, Incident, MonitoringRun, ResponseAction
from backend.services.monitoring import close_run


def add_run_and_actions(engine, admin_id):
    with Session(engine) as session:
        session.add(MonitoringRun(started_by_id=admin_id))
        incident = Incident(rule_code="arp_spoof", source_ip="192.168.1.21", target_ip="192.168.1.1", severity="Critical")
        session.add(incident)
        session.flush()
        for key, mac in [("pending", "02:00:00:00:00:21"), ("approved", "02:00:00:00:00:22")]:
            session.add(ResponseAction(
                incident_id=incident.id, request_key=key, action_type="block",
                target_mac=mac, reason="test",
            ))
        session.commit()


def approval_states(engine):
    with Session(engine) as session:
        actions = session.scalars(select(ResponseAction).order_by(ResponseAction.id)).all()
        return [(action.approval_status, action.decided_by_id is not None, action.decided_at is not None) for action in actions]


def test_stop_cancels_pending_approvals(admin_api, database):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    add_run_and_actions(engine, admin_id)

    with Session(engine) as session:
        action_id = session.scalar(select(ResponseAction.id).where(ResponseAction.request_key == "approved"))
    assert admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"}).status_code == 200

    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    assert approval_states(engine) == [("cancelled", True, True), ("approved", True, True)]

    with Session(engine) as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.event_type == "response_action.cancelled"))
        assert event.administrator_id == admin_id
        assert event.details_json == {"reason": "monitoring stopped"}

    detail = admin_api.get("/api/actions", params={"approval": "cancelled"}).json()
    assert detail[0]["decided_by"]["username"] == "admin"


def test_failure_or_restart_also_cancels(admin_api, database):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    add_run_and_actions(engine, admin_id)

    close_run(engine, "interrupted")
    assert approval_states(engine) == [("cancelled", False, True), ("cancelled", False, True)]


def test_nothing_cancelled_without_a_running_monitor(admin_api, database):
    engine, _, _ = database
    admin_id = admin_api.get("/api/auth/me").json()["id"]
    add_run_and_actions(engine, admin_id)
    close_run(engine, "interrupted")

    with Session(engine) as session:
        incident_id = session.scalar(select(Incident.id))
        session.add(ResponseAction(
            incident_id=incident_id, request_key="later", action_type="block",
            target_mac="02:00:00:00:00:23", reason="test",
        ))
        session.commit()

    close_run(engine, "interrupted")
    assert approval_states(engine)[2] == ("pending", False, False)