from datetime import timedelta
from unittest.mock import Mock

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Device, Incident, MonitoringRun, ResponseAction
from backend.services import response_execution
from gateway import discovery, firewall, firewall_client


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


def configure_enforcement(monkeypatch, engine, action_id):
    monkeypatch.setenv("INDS_FIREWALL_ENABLED", "1")
    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "ap0")
    monkeypatch.setenv("INDS_MONITOR_AP_MAC", "02:00:00:00:00:01")
    with Session(engine) as session, session.begin():
        action = session.get(ResponseAction, action_id)
        mac = action.target_mac
        action.device = Device(mac_address=mac)
    monkeypatch.setattr(discovery, "macs_on_port", Mock(return_value={mac}))
    return mac


def test_routed_proposal_approval_expiration_and_restart(admin_api, database, monkeypatch):
    engine = database[0]
    mac = "02:00:00:00:00:42"
    address = "192.168.50.121"
    with Session(engine) as session, session.begin():
        device = Device(mac_address=mac, current_ip=address, ip_source="dhcp_lease")
        incident = Incident(rule_code="TRAFFIC_SPIKE", source_ip=address, target_ip="multiple",
                            severity="Critical", risk_score=85, source_device=device)
        session.add(incident)
        session.flush()
        incident_id = incident.id
    monkeypatch.setenv("INDS_FIREWALL_ENABLED", "1")
    monkeypatch.setenv("INDS_MONITOR_INTERFACE", "eth1")
    monkeypatch.setenv("INDS_MONITOR_AP_MAC", "02:00:00:00:00:01")
    monkeypatch.setenv("INDS_PROTECTED_MACS", "02:00:00:00:00:02")
    monkeypatch.setattr(discovery, "read_neighbors", Mock(return_value=[{"mac": mac, "ip": address}]))
    set_block = Mock()
    clear_blocks = Mock()
    monkeypatch.setattr(firewall_client, "set_block", set_block)
    monkeypatch.setattr(firewall_client, "clear_blocks", clear_blocks)

    incident = admin_api.get(f"/api/incidents/{incident_id}").json()
    assert incident["policy"]["recommendation"] == "temporary_block"
    payload = {"incident_id": incident_id, "reason": "Contain while investigating", "duration_minutes": 1}
    proposed = admin_api.post("/api/actions", json=payload)
    assert proposed.status_code == 201
    assert proposed.json()["approval_status"] == "pending"
    assert proposed.json()["expires_at"]
    assert admin_api.post("/api/actions", json=payload).status_code == 409
    set_block.assert_not_called()

    start_monitoring(admin_api, engine)
    action_id = proposed.json()["id"]
    applied = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"})
    assert applied.status_code == 200
    assert applied.json()["execution_status"] == "active"
    assert set_block.call_args.args == (mac, True)
    assert 0 < set_block.call_args.kwargs["timeout_seconds"] <= 60

    with monkeypatch.context() as future:
        future.setattr(response_execution, "utc_now", lambda: utc_now() + timedelta(minutes=2))
        response_execution.expire_blocks(engine)
    assert set_block.call_args.args == (mac, False)
    second = admin_api.post("/api/actions", json=payload).json()["id"]
    assert admin_api.post(f"/api/actions/{second}/decision", json={"decision": "approved"}).status_code == 200
    response_execution.reconcile_blocks(engine)
    clear_blocks.assert_called_once_with()
    with Session(engine) as session:
        assert session.get(ResponseAction, action_id).execution_status == "removed"
        assert session.get(ResponseAction, second).execution_status == "removed"
        assert list(session.scalars(select(AuditEvent.event_type).where(AuditEvent.response_action_id == action_id)
                                    .order_by(AuditEvent.id))) == [
            "response_action.proposed", "response_action.approved", "response_action.applied",
            "response_action.expiry_due", "response_action.cleared",
        ]


def test_expired_pending_proposal_cancels_without_firewall(database, monkeypatch):
    engine = database[0]
    _, action_id = add_incident_with_response(engine)
    with Session(engine) as session, session.begin():
        action = session.get(ResponseAction, action_id)
        action.expires_at = utc_now() + timedelta(minutes=1)
    monkeypatch.setenv("INDS_FIREWALL_ENABLED", "0")
    monkeypatch.setattr(response_execution, "utc_now", lambda: utc_now() + timedelta(minutes=2))
    set_block = Mock()
    monkeypatch.setattr(firewall, "set_block", set_block)
    response_execution.expire_blocks(engine)
    set_block.assert_not_called()
    with Session(engine) as session:
        assert session.get(ResponseAction, action_id).approval_status == "cancelled"
        event = session.scalar(select(AuditEvent).where(AuditEvent.response_action_id == action_id))
        assert event.event_type == "response_action.proposal_expired"


def test_approved_block_is_confirmed_and_idempotently_reversed(admin_api, database, monkeypatch):
    engine, _, _ = database
    _, action_id = add_incident_with_response(engine)
    start_monitoring(admin_api, engine)
    mac = configure_enforcement(monkeypatch, engine, action_id)
    set_block = Mock()
    monkeypatch.setattr(firewall, "set_block", set_block)
    path = f"/api/actions/{action_id}"

    applied = admin_api.post(path + "/decision", json={"decision": "approved"})
    assert applied.status_code == 200
    assert applied.json()["execution_status"] == "active"
    assert applied.json()["applied_at"]
    removed = admin_api.post(path + "/reverse")
    assert removed.json()["execution_status"] == "removed"
    assert removed.json()["removed_at"]
    assert admin_api.post(path + "/reverse").json()["execution_status"] == "removed"
    assert [call.args for call in set_block.call_args_list] == [(mac, True), (mac, False)]


def test_unconfirmed_application_is_visible_and_stop_clears_it(admin_api, database, monkeypatch):
    engine, _, _ = database
    _, action_id = add_incident_with_response(engine)
    start_monitoring(admin_api, engine)
    configure_enforcement(monkeypatch, engine, action_id)
    monkeypatch.setattr(firewall, "set_block", Mock(side_effect=OSError("unreachable")))
    clear = Mock(side_effect=[OSError("unreachable"), None])
    monkeypatch.setattr(firewall, "clear_blocks", clear)

    applied = admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"})
    assert applied.json()["execution_status"] == "unknown"
    assert applied.json()["applied_at"] is None
    assert admin_api.post("/api/system/monitoring/stop").status_code == 503
    assert admin_api.get("/api/system/status").json()["firewall_cleanup_needed"]
    assert admin_api.post("/api/system/monitoring/stop").status_code == 204
    assert not admin_api.get("/api/system/status").json()["firewall_cleanup_needed"]
    with Session(engine) as session:
        assert session.get(ResponseAction, action_id).execution_status == "not_applied"


def test_protected_inventory_device_cannot_be_blocked(admin_api, database, monkeypatch):
    engine, _, _ = database
    _, action_id = add_incident_with_response(engine)
    start_monitoring(admin_api, engine)
    mac = configure_enforcement(monkeypatch, engine, action_id)
    monkeypatch.setenv("INDS_MONITOR_AP_MAC", mac)
    set_block = Mock()
    monkeypatch.setattr(firewall, "set_block", set_block)
    assert admin_api.post(f"/api/actions/{action_id}/decision", json={"decision": "approved"}).status_code == 409
    set_block.assert_not_called()


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
