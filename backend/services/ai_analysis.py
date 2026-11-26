import logging
from datetime import timedelta
from threading import Event, Thread

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import AIAnalysis
from backend.services import deepseek
from backend.services.ai_context import build_context
from backend.services.ai_recommendation import propose_response
from backend.services.audit import record_event

logger = logging.getLogger(__name__)

PROMPT_VERSION = "v1"
MAX_ATTEMPTS = 3
RETRY_WAITS = (30, 120)
CHECK_SECONDS = 2


def has_active_analysis(session, incident_id):
    return session.scalar(
        select(AIAnalysis.id).where(AIAnalysis.incident_id == incident_id, AIAnalysis.status.in_(("pending", "running")))
    ) is not None


def queue_analysis(session, incident, wait_seconds=0):
    if has_active_analysis(session, incident.id):
        return None
    analysis = AIAnalysis(
        incident_id=incident.id,
        model=deepseek.model_name(),
        prompt_version=PROMPT_VERSION,
        status="pending",
        input_summary_json={},
        requested_at=utc_now() + timedelta(seconds=wait_seconds),
    )
    session.add(analysis)
    session.flush()
    return analysis


def failed_in_a_row(session, incident_id):
    statuses = session.scalars(
        select(AIAnalysis.status).where(AIAnalysis.incident_id == incident_id).order_by(AIAnalysis.id.desc())
    )
    count = 0
    for status in statuses:
        if status != "failed":
            break
        count += 1
    return count


def monitoring_stopped(incident):
    return incident.monitoring_run is not None and incident.monitoring_run.ended_at is not None


def reset_interrupted(engine):
    with Session(engine) as session, session.begin():
        session.execute(
            update(AIAnalysis).where(AIAnalysis.status == "running").values(status="pending", started_at=None)
        )


def start_next(engine):
    with Session(engine) as session, session.begin():
        analysis = session.scalar(
            select(AIAnalysis)
            .where(AIAnalysis.status == "pending", AIAnalysis.requested_at <= utc_now())
            .order_by(AIAnalysis.requested_at, AIAnalysis.id)
            .limit(1)
        )
        if analysis is None:
            return None
        if monitoring_stopped(analysis.incident):
            analysis.status = "cancelled"
            analysis.completed_at = utc_now()
            return analysis.id, None
        analysis.status = "running"
        analysis.started_at = utc_now()
        analysis.input_summary_json = build_context(session, analysis.incident)
        return analysis.id, analysis.input_summary_json


def save_result(engine, analysis_id, assessment=None, error=None):
    with Session(engine) as session, session.begin():
        analysis = session.get(AIAnalysis, analysis_id)
        if analysis is None or analysis.status != "running":
            return
        if monitoring_stopped(analysis.incident):
            analysis.status = "cancelled"
            analysis.completed_at = utc_now()
            return

        if error is None:
            assessment = propose_response(session, analysis, assessment)
            analysis.status = "succeeded"
            analysis.assessment_json = assessment
            analysis.completed_at = utc_now()
            record_event(
                session, "ai_analysis.attached", incident_id=analysis.incident_id, ai_analysis_id=analysis.id,
                details={"model": analysis.model, "risk_level": assessment["risk_level"]},
            )
            return

        analysis.status = "failed"
        analysis.error_message = str(error)
        analysis.completed_at = utc_now()
        session.flush()
        record_event(
            session, "ai_analysis.failed", outcome="failure", incident_id=analysis.incident_id,
            ai_analysis_id=analysis.id, details={"model": analysis.model, "error": str(error)},
        )
        failures = failed_in_a_row(session, analysis.incident_id)
        if error.retry and failures < MAX_ATTEMPTS:
            queue_analysis(session, analysis.incident, RETRY_WAITS[failures - 1])


def process_next(engine):
    job = start_next(engine)
    if job is None:
        return False
    analysis_id, context = job
    if context is None:
        return True
    try:
        assessment = deepseek.ask_deepseek(context)
    except deepseek.DeepSeekError as error:
        logger.warning("AI analysis %s failed: %s", analysis_id, error)
        save_result(engine, analysis_id, error=error)
    except Exception:
        logger.exception("AI analysis %s crashed", analysis_id)
        save_result(engine, analysis_id, error=deepseek.DeepSeekError("Unexpected error during the analysis.", retry=False))
    else:
        save_result(engine, analysis_id, assessment=assessment)
    return True


class AnalysisWorker:
    def __init__(self):
        self.stop_event = Event()
        self.thread = None

    def start(self, engine):
        if self.thread is not None and self.thread.is_alive():
            return
        reset_interrupted(engine)
        self.stop_event.clear()
        self.thread = Thread(target=self.run, args=(engine,), name="inds-ai-analysis", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            self.thread = None

    def run(self, engine):
        while not self.stop_event.is_set():
            try:
                busy = process_next(engine)
            except Exception:
                logger.exception("AI analysis worker error")
                busy = False
            if not busy:
                self.stop_event.wait(CHECK_SECONDS)
