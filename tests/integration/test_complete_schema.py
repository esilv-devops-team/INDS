"""Relational integrity and state invariants for the approved complete schema."""

from datetime import datetime, timedelta

from alembic import command
import pytest
from sqlalchemy import delete, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.database.models import (
    Administrator, AIAnalysis, AuditEvent, Device, Incident, MonitoringRun,
    ResponseAction, TrafficSummary,
)

NOW = datetime(2026, 1, 1)
LATER = NOW + timedelta(minutes=1)


@pytest.fixture
def records(database):
    engine, _, _ = database
    with Session(engine) as session:
        admin = Administrator(username=" Admin ", password_hash="test-only-hash", created_at=NOW)
        device = Device(mac_address="B8:27:EB:12:34:56")
        run = MonitoringRun(started_by=admin, started_at=NOW)
        incident = Incident(source_device=device, monitoring_run=run, rule_code="port_scan",
                            source_ip="192.168.50.66", target_ip="192.168.50.20")
        analysis = AIAnalysis(incident=incident, model="deepseek-chat", prompt_version="v1",
                              input_summary_json={"distinct_ports": 20}, requested_at=NOW)
        action = ResponseAction(incident=incident, device=device, ai_analysis=analysis,
                                request_key="request-1", action_type="block",
                                target_mac=device.mac_address, reason="Port scan",
                                requested_by=admin, created_at=NOW, updated_at=NOW)
        traffic = TrafficSummary(device=device, monitoring_run=run, window_start=NOW, window_end=LATER)
        audit = AuditEvent(actor_type="administrator", administrator=admin, event_type="response.proposed",
                           outcome="success", device=device, incident=incident,
                           monitoring_run=run, ai_analysis=analysis, response_action=action,
                           details_json={"target_mac": device.mac_address})
        session.add_all([action, traffic, audit])
        session.commit()
        yield session, dict(admin=admin, device=device, run=run, incident=incident,
                            analysis=analysis, action=action, traffic=traffic, audit=audit)


def test_all_entities_persist_with_relationships(records):
    session, rows = records
    session.expire_all()
    assert rows["admin"].username == "admin"
    assert rows["run"].started_by.id == rows["admin"].id
    assert rows["incident"].monitoring_run.id == rows["run"].id
    assert rows["analysis"].incident.id == rows["incident"].id
    assert rows["action"].ai_analysis.id == rows["analysis"].id
    assert rows["action"].requested_by.id == rows["admin"].id
    assert rows["traffic"].bytes_sent == 0
    assert rows["audit"].response_action.id == rows["action"].id
    for model in (Administrator, Device, MonitoringRun, Incident, TrafficSummary,
                  AIAnalysis, ResponseAction, AuditEvent):
        assert session.scalar(select(model)) is not None


def test_only_one_unfinished_run_across_all_administrators(records):
    session, rows = records
    another = Administrator(username="second", password_hash="test-only-hash")
    session.add(MonitoringRun(started_by=another))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    rows["run"].ended_at = LATER
    rows["run"].stop_reason = "administrator"
    rows["run"].stopped_by = rows["admin"]
    session.commit()
    session.add(MonitoringRun(started_by=rows["admin"], started_at=LATER))
    session.commit()


@pytest.mark.parametrize("changes", [
    {"ended_at": LATER}, {"stop_reason": "failure"},
    {"ended_at": NOW - timedelta(seconds=1), "stop_reason": "failure"},
    {"ended_at": LATER, "stop_reason": "administrator"},
    {"ended_at": LATER, "stop_reason": "invalid"},
])
def test_monitoring_state_constraints(records, changes):
    session, rows = records
    for key, value in changes.items():
        setattr(rows["run"], key, value)
    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("field", ["bytes_sent", "bytes_received", "packets_sent", "packets_received", "connection_count"])
@pytest.mark.parametrize("value", [-1, 1.5])
def test_traffic_counters_are_nonnegative_integers(records, field, value):
    session, rows = records
    setattr(rows["traffic"], field, value)
    with pytest.raises(IntegrityError):
        session.commit()


def test_traffic_window_and_uniqueness(records):
    session, rows = records
    rows["traffic"].window_end = NOW
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    session.add(TrafficSummary(device=rows["device"], monitoring_run=rows["run"],
                               window_start=NOW, window_end=LATER))
    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("changes", [
    {"status": "invalid"}, {"status": "running"}, {"status": "succeeded"},
    {"status": "failed", "completed_at": LATER},
    {"status": "cancelled"}, {"completed_at": LATER},
    {"started_at": NOW - timedelta(seconds=1)},
    {"input_summary_json": []}, {"input_summary_json": None},
    {"assessment_json": []},
    {"status": "succeeded", "started_at": NOW, "completed_at": LATER},
])
def test_ai_analysis_constraints(records, changes):
    session, rows = records
    for key, value in changes.items():
        setattr(rows["analysis"], key, value)
    with pytest.raises(IntegrityError):
        session.commit()


def test_analysis_success_and_retry(records):
    session, rows = records
    analysis = rows["analysis"]
    analysis.status, analysis.started_at, analysis.completed_at = "succeeded", NOW, LATER
    analysis.assessment_json = {"assessment": "Suspicious", "recommendations": ["block"]}
    retry = AIAnalysis(incident=rows["incident"], model="deepseek-chat", prompt_version="v2",
                       input_summary_json={}, status="failed", requested_at=NOW,
                       completed_at=LATER, error_message="Connection failed")
    session.add(retry)
    session.commit()
    assert retry.id != analysis.id
    assert rows["incident"].risk_score is None


@pytest.mark.parametrize("changes", [
    {"action_type": "invalid"}, {"action_type": "rate_limit"},
    {"rate_limit_kbps": 100}, {"action_type": "rate_limit", "rate_limit_kbps": 0},
    {"action_type": "rate_limit", "rate_limit_kbps": 1.5},
    {"approval_status": "approved"}, {"approval_status": "rejected"},
    {"approval_status": "cancelled"}, {"approval_status": "invalid"},
    {"execution_status": "applying"}, {"execution_status": "active"},
    {"execution_status": "invalid"}, {"removed_at": LATER},
    {"expires_at": NOW}, {"reason": " "}, {"request_key": ""},
])
def test_action_constraints(records, changes):
    session, rows = records
    for key, value in changes.items():
        setattr(rows["action"], key, value)
    with pytest.raises(IntegrityError):
        session.commit()


def test_action_approval_execution_and_removal(records):
    session, rows = records
    action = rows["action"]
    action.action_type, action.rate_limit_kbps = "rate_limit", 1024
    action.approval_status, action.decided_by, action.decided_at = "approved", rows["admin"], NOW
    session.commit()
    action.execution_status = "applying"
    session.commit()
    action.execution_status, action.applied_at, action.expires_at = "active", NOW, LATER
    session.commit()
    action.execution_status = "removing"
    session.commit()
    action.execution_status, action.removed_at = "removed", LATER
    session.commit()
    assert action.decided_by.id == rows["admin"].id


def test_administrator_uniqueness_and_inactive_identity_retention(records):
    session, rows = records
    session.add(Administrator(username="ADMIN", password_hash="another-test-hash"))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    rows["admin"].is_active = False
    session.commit()
    assert rows["action"].requested_by.username == "admin"


def test_sql_errors_do_not_expose_administrator_credentials(records, caplog):
    session, rows = records
    credential = "test-only-sensitive-password-hash"
    session.add(Administrator(username=rows["admin"].username, password_hash=credential))
    with caplog.at_level("INFO", logger="sqlalchemy.engine"):
        with pytest.raises(IntegrityError) as failure:
            session.commit()
    assert credential not in str(failure.value)
    assert credential not in caplog.text


def test_ending_monitoring_does_not_remove_active_responses_or_history(records):
    session, rows = records
    action = rows["action"]
    action.approval_status, action.decided_by, action.decided_at = "approved", rows["admin"], NOW
    action.execution_status, action.applied_at = "active", NOW
    rows["run"].ended_at = LATER
    rows["run"].stop_reason = "administrator"
    rows["run"].stopped_by = rows["admin"]
    session.commit()
    session.expire_all()
    assert action.execution_status == "active"
    assert rows["incident"].monitoring_run_id == rows["run"].id
    assert session.scalar(select(TrafficSummary)) is not None
    assert session.scalar(select(AuditEvent)) is not None


def test_system_event_and_cancelled_analysis(records):
    session, rows = records
    event = AuditEvent(actor_type="system", event_type="monitoring.interrupted",
                       outcome="failure", monitoring_run=rows["run"])
    session.add(event)
    rows["analysis"].status = "cancelled"
    rows["analysis"].completed_at = LATER
    rows["action"].approval_status = "cancelled"
    rows["action"].decided_at = LATER
    session.commit()
    assert event.administrator_id is None
    assert event.details_json == {}


def test_response_request_key_prevents_duplicates(records):
    session, rows = records
    session.add(ResponseAction(request_key=rows["action"].request_key, action_type="block",
                               target_mac=rows["device"].mac_address, reason="Duplicate"))
    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("changes", [
    {"actor_type": "system"}, {"administrator_id": None},
    {"outcome": "invalid"}, {"details_json": []}, {"details_json": None},
    {"event_type": " "},
])
def test_audit_constraints(records, changes):
    session, rows = records
    for key, value in changes.items():
        setattr(rows["audit"], key, value)
    with pytest.raises(IntegrityError):
        session.commit()


@pytest.mark.parametrize("record, field", [
    ("run", "started_by_id"), ("run", "stopped_by_id"),
    ("incident", "monitoring_run_id"), ("traffic", "device_id"),
    ("traffic", "monitoring_run_id"), ("analysis", "incident_id"),
    ("action", "incident_id"), ("action", "device_id"), ("action", "ai_analysis_id"),
    ("action", "requested_by_id"), ("audit", "response_action_id"),
    ("audit", "monitoring_run_id"), ("audit", "ai_analysis_id"),
])
def test_foreign_keys_reject_missing_references(records, record, field):
    session, rows = records
    setattr(rows[record], field, 99999)
    with pytest.raises(IntegrityError):
        session.commit()


def test_history_retention_and_deletion_policies(records):
    session, rows = records
    for model, key in ((Administrator, "admin"), (Device, "device"),
                       (Incident, "incident"), (AIAnalysis, "analysis"), (MonitoringRun, "run")):
        with pytest.raises(IntegrityError):
            session.execute(delete(model).where(model.id == rows[key].id))
        session.rollback()
    rows["admin"].is_active = False
    session.commit()
    session.execute(delete(TrafficSummary))
    session.execute(delete(Device))
    session.commit()
    session.expire_all()
    assert rows["incident"].source_device_id is None
    assert rows["action"].device_id is None
    assert rows["action"].target_mac == "B8:27:EB:12:34:56"
    assert rows["audit"].device_id is None
    session.execute(delete(ResponseAction))
    session.execute(delete(AIAnalysis))
    session.execute(delete(Incident))
    session.execute(delete(MonitoringRun))
    session.commit()
    session.expire_all()
    assert rows["audit"].response_action_id is None
    assert rows["audit"].incident_id is None
    assert rows["audit"].details_json["target_mac"] == "B8:27:EB:12:34:56"


def test_upgrade_preserves_revision_0001_records(database):
    engine, config, _ = database
    command.downgrade(config, "0001")
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO devices VALUES (7, '00:11:22:33:44:55', NULL, NULL, NULL, 0, :now, :now)"), {"now": NOW.isoformat(" ")})
        connection.execute(text("INSERT INTO incidents (id, source_device_id, rule_code, source_ip, target_ip, "
                                "first_seen_at, last_seen_at, status, evidence_json, created_at, updated_at) "
                                "VALUES (9, 7, 'port_scan', '192.168.50.66', '192.168.50.20', :now, :now, "
                                "'open', :evidence, :now, :now)"),
                           {"now": NOW.isoformat(" "), "evidence": '{"distinct_ports":20}'})
    command.upgrade(config, "head")
    with Session(engine) as session:
        incident = session.get(Incident, 9)
        assert incident.source_device.id == 7
        assert incident.monitoring_run_id is None
        assert incident.evidence_json == {"distinct_ports": 20}
    command.downgrade(config, "0001")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT id FROM incidents")) == 9
        assert connection.scalar(text("SELECT id FROM devices")) == 7
    command.upgrade(config, "head")
    command.check(config)


def test_invalid_legacy_evidence_rolls_back_the_entire_upgrade(database):
    engine, config, _ = database
    command.downgrade(config, "0001")
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO incidents (id, rule_code, source_ip, target_ip, "
            "first_seen_at, last_seen_at, status, evidence_json, created_at, updated_at) "
            "VALUES (9, 'port_scan', '192.168.50.66', '192.168.50.20', :now, :now, "
            "'open', :evidence, :now, :now)"
        ), {"now": NOW.isoformat(" "), "evidence": "[]"})
    with pytest.raises(IntegrityError):
        command.upgrade(config, "head")
    assert set(inspect(engine).get_table_names()) == {"devices", "incidents", "alembic_version"}
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0001"
        assert connection.scalar(text("SELECT evidence_json FROM incidents WHERE id = 9")) == "[]"


def test_populated_downgrade_preserves_original_inventory_and_incidents(records, database):
    session, rows = records
    device_id, incident_id = rows["device"].id, rows["incident"].id
    session.close()
    engine, config, _ = database
    command.downgrade(config, "0001")
    assert set(inspect(engine).get_table_names()) == {"devices", "incidents", "alembic_version"}
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT id FROM devices")) == device_id
        assert connection.scalar(text("SELECT id FROM incidents")) == incident_id
    command.upgrade(config, "head")
    with Session(engine) as reader:
        incident = reader.get(Incident, incident_id)
        assert incident.source_device.id == device_id
        assert incident.monitoring_run_id is None
