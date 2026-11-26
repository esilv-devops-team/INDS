from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.models import Administrator, AuditEvent, Incident, MonitoringRun, ResponseAction
from backend.database.session import get_session
from backend.services.live_traffic import feed, watch
from backend.services.monitoring import configured_interface

router = APIRouter(prefix="/api/live", tags=["live"])

EVENT_TYPES = (
    "incident.created", "incident.escalated", "ai_analysis.attached", "ai_analysis.failed",
    "response_action.proposed", "response_action.approved", "response_action.rejected",
    "response_action.applied", "response_action.cleared",
)
FIRST_EVENTS = 20
MAX_EVENTS = 50


def current_run(session):
    return session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)).limit(1))


def incident_sources(session, run):
    sources = {}
    incidents = session.scalars(
        select(Incident).where(Incident.monitoring_run_id == run.id, Incident.status != "resolved").order_by(Incident.id)
    )
    for incident in incidents:
        mac = incident.source_device.mac_address if incident.source_device else incident.evidence_json.get("observed_source_mac")
        if mac:
            sources[mac.upper()] = incident.id
    return sources


def active_blocks(session):
    rows = session.execute(
        select(ResponseAction.target_mac, ResponseAction.applied_at)
        .where(ResponseAction.action_type == "block", ResponseAction.execution_status == "active")
    ).all()
    return {mac.upper(): applied_at.replace(tzinfo=UTC).timestamp() for mac, applied_at in rows if applied_at}


def live_status(session):
    run = current_run(session)
    if run is not None:
        mode = "protect"
    elif watch.running():
        mode = "watch"
    else:
        mode = "off"
    return run, {"mode": mode, "interface": configured_interface() or None, "watch_seconds_left": watch.seconds_left()}


@router.get("")
def live_packets(
    after: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    run, status = live_status(session)
    if status["mode"] == "watch":
        watch.touch()
    packets, last = feed.since(after)
    sources = incident_sources(session, run) if run is not None else {}
    blocks = active_blocks(session)
    for packet in packets:
        packet["incident_id"] = None
        packet["dropped"] = False
        if packet["mode"] != "protect":
            continue
        packet["incident_id"] = sources.get(packet["source_mac"])
        applied = blocks.get(packet["source_mac"])
        packet["dropped"] = applied is not None and packet["time"] >= applied
    return {**status, "last": last, "packets": packets, "rates": feed.rates()}


@router.post("/watch")
def start_watch(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    if current_run(session) is not None:
        raise HTTPException(status_code=409, detail="INDS is ON, the live view already uses its capture.")
    interface = configured_interface()
    if not interface:
        raise HTTPException(status_code=503, detail="Set INDS_MONITOR_INTERFACE to the AP-facing port.")
    try:
        watch.start(interface)
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Unable to open traffic capture on {interface}.") from error
    return live_status(session)[1]


@router.delete("/watch", status_code=204)
def stop_watch(admin: Administrator = Depends(get_current_admin)):
    watch.stop()


@router.get("/events")
def live_events(
    after: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    query = select(AuditEvent).where(AuditEvent.event_type.in_(EVENT_TYPES), AuditEvent.incident_id.is_not(None))
    if after:
        events = session.scalars(query.where(AuditEvent.id > after).order_by(AuditEvent.id).limit(MAX_EVENTS)).all()
    else:
        events = list(reversed(session.scalars(query.order_by(AuditEvent.id.desc()).limit(FIRST_EVENTS)).all()))
    return [
        {"id": event.id, "occurred_at": event.occurred_at, "event_type": event.event_type,
         "incident_id": event.incident_id, "details": event.details_json}
        for event in events
    ]
