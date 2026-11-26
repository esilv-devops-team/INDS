import time
from datetime import UTC, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Device, Incident, MonitoringRun
from backend.services import ai_analysis, deepseek
from backend.services.ai_analysis import AnalysisWorker, process_next, queue_analysis, reset_interrupted
from backend.services.deepseek import DeepSeekError
from backend.services.incident_creation import record_findings
from detection.base import Finding

NOW = utc_now().replace(microsecond=0)
ASSESSMENT = {"summary": "device-1 scans device-2.", "risk_level": "High", "recommended_action": "block"}


def detect(engine):
    with Session(engine) as session, session.begin():
        admin = Administrator(username="setup", password_hash="x")
        session.add(admin)
        session.flush()
        run = MonitoringRun(started_by_id=admin.id, started_at=NOW - timedelta(hours=1))
        scanner = Device(mac_address="02:00:00:00:00:66", current_ip="192.168.50.66",
                         first_seen_at=NOW - timedelta(days=1), last_seen_at=NOW)
        session.add_all([run, scanner])
        session.flush()
        finding = Finding("PORT_SCAN", scanner.id, NOW.replace(tzinfo=UTC), "Medium",
                          {"source_ip": "192.168.50.66", "target_ip": "192.168.50.20"}, {"distinct_ports": 20})
        (incident, _), = record_findings(session, run.id, [finding])
        return incident.id, run.id


def analyses(engine, incident_id):
    with Session(engine) as session:
        rows = session.scalars(select(AIAnalysis).where(AIAnalysis.incident_id == incident_id).order_by(AIAnalysis.id)).all()
        session.expunge_all()
        return rows


def make_due(engine):
    with Session(engine) as session, session.begin():
        for analysis in session.scalars(select(AIAnalysis).where(AIAnalysis.status == "pending")):
            analysis.requested_at = utc_now() - timedelta(seconds=1)


def end_run(engine, run_id):
    with Session(engine) as session, session.begin():
        run = session.get(MonitoringRun, run_id)
        run.ended_at, run.stop_reason = utc_now(), "shutdown"


def events(engine, event_type):
    with Session(engine) as session:
        return [(event.outcome, event.details_json) for event in
                session.scalars(select(AuditEvent).where(AuditEvent.event_type == event_type))]


@pytest.fixture
def answer(monkeypatch):
    replies = []
    seen = []

    def fake(context):
        seen.append(context)
        result = replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(deepseek, "ask_deepseek", fake)
    return replies, seen


def test_successful_analysis(database, answer):
    engine, _, _ = database
    replies, seen = answer
    incident_id, _ = detect(engine)
    replies.append(ASSESSMENT)

    assert process_next(engine)
    assert not process_next(engine)

    analysis, = analyses(engine, incident_id)
    assert (analysis.status, analysis.prompt_version) == ("succeeded", "v1")
    assert analysis.assessment_json == {**ASSESSMENT, "response_note": "Block not proposed: the policy only blocks "
                                        "High or Critical incidents (this one is Medium)."}
    assert analysis.started_at is not None and analysis.completed_at is not None
    assert analysis.input_summary_json == seen[0]
    assert seen[0]["threat_type"] == "PORT_SCAN"
    assert "192.168.50.66" not in str(seen[0])
    assert events(engine, "ai_analysis.attached") == [("success", {"model": "deepseek-flash", "risk_level": "High"})]


def test_no_duplicate_requests(database):
    engine, _, _ = database
    incident_id, _ = detect(engine)
    with Session(engine) as session, session.begin():
        assert queue_analysis(session, session.get(Incident, incident_id)) is None
    assert len(analyses(engine, incident_id)) == 1


def test_waiting_analysis_is_not_started_early(database, answer):
    engine, _, _ = database
    incident_id, _ = detect(engine)
    with Session(engine) as session, session.begin():
        session.scalar(select(AIAnalysis)).requested_at = utc_now() + timedelta(minutes=1)
    assert not process_next(engine)
    assert analyses(engine, incident_id)[0].status == "pending"


def test_retries_then_gives_up(database, answer):
    engine, _, _ = database
    replies, _ = answer
    incident_id, _ = detect(engine)
    replies.extend([DeepSeekError("DeepSeek did not answer in time.")] * 3)

    started = utc_now()
    assert process_next(engine)
    first, second = analyses(engine, incident_id)
    assert (first.status, first.error_message) == ("failed", "DeepSeek did not answer in time.")
    assert second.status == "pending"
    assert 29 <= (second.requested_at - started).total_seconds() <= 32
    assert not process_next(engine)

    make_due(engine)
    started = utc_now()
    assert process_next(engine)
    third = analyses(engine, incident_id)[2]
    assert 119 <= (third.requested_at - started).total_seconds() <= 122

    make_due(engine)
    assert process_next(engine)
    rows = analyses(engine, incident_id)
    assert [row.status for row in rows] == ["failed", "failed", "failed"]
    assert len(events(engine, "ai_analysis.failed")) == 3
    assert events(engine, "ai_analysis.failed")[0] == (
        "failure", {"model": "deepseek-flash", "error": "DeepSeek did not answer in time."})


def test_retry_succeeds(database, answer):
    engine, _, _ = database
    replies, _ = answer
    incident_id, _ = detect(engine)
    replies.extend([DeepSeekError("Could not reach the DeepSeek API."), ASSESSMENT])
    process_next(engine)
    make_due(engine)
    process_next(engine)
    assert [row.status for row in analyses(engine, incident_id)] == ["failed", "succeeded"]


@pytest.mark.parametrize("problem, message", [
    (DeepSeekError("DeepSeek API key not configured.", retry=False), "DeepSeek API key not configured."),
    (RuntimeError("boom"), "Unexpected error during the analysis."),
])
def test_errors_without_retry(database, answer, problem, message):
    engine, _, _ = database
    replies, _ = answer
    incident_id, _ = detect(engine)
    replies.append(problem)
    process_next(engine)
    analysis, = analyses(engine, incident_id)
    assert (analysis.status, analysis.error_message) == ("failed", message)


def test_monitoring_off_cancels_waiting_analysis(database, answer):
    engine, _, _ = database
    replies, seen = answer
    incident_id, run_id = detect(engine)
    end_run(engine, run_id)
    assert process_next(engine)
    analysis, = analyses(engine, incident_id)
    assert analysis.status == "cancelled"
    assert analysis.completed_at is not None
    assert seen == []


def test_late_result_is_discarded(database, monkeypatch):
    engine, _, _ = database
    incident_id, run_id = detect(engine)

    def slow_answer(context):
        end_run(engine, run_id)
        return ASSESSMENT

    monkeypatch.setattr(deepseek, "ask_deepseek", slow_answer)
    process_next(engine)
    analysis, = analyses(engine, incident_id)
    assert (analysis.status, analysis.assessment_json) == ("cancelled", None)
    assert events(engine, "ai_analysis.attached") == []


def test_restart_requeues_running_analysis(database, answer):
    engine, _, _ = database
    incident_id, _ = detect(engine)
    with Session(engine) as session, session.begin():
        analysis = session.scalar(select(AIAnalysis))
        analysis.status, analysis.started_at = "running", utc_now()
    reset_interrupted(engine)
    analysis, = analyses(engine, incident_id)
    assert (analysis.status, analysis.started_at) == ("pending", None)


def test_worker_runs_in_background(database, answer, monkeypatch):
    engine, _, _ = database
    replies, _ = answer
    monkeypatch.setattr(ai_analysis, "CHECK_SECONDS", 0.05)
    worker = AnalysisWorker()
    worker.start(engine)
    worker.start(engine)
    try:
        replies.append(ASSESSMENT)
        incident_id, _ = detect(engine)
        for _ in range(100):
            if analyses(engine, incident_id)[0].status == "succeeded":
                break
            time.sleep(0.05)
        assert analyses(engine, incident_id)[0].status == "succeeded"
    finally:
        worker.stop()
    assert worker.thread is None


def test_worker_survives_errors(database, monkeypatch):
    engine, _, _ = database
    calls = []

    def broken(_engine):
        calls.append(1)
        raise RuntimeError("database locked")

    monkeypatch.setattr(ai_analysis, "process_next", broken)
    monkeypatch.setattr(ai_analysis, "CHECK_SECONDS", 0.01)
    worker = AnalysisWorker()
    worker.start(engine)
    time.sleep(0.1)
    worker.stop()
    assert len(calls) > 1
