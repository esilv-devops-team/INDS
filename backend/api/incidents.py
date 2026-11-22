from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.api.actions import ActionOut
from backend.api.auth import get_current_admin
from backend.api.devices import DeviceOut
from backend.database.base import utc_now
from backend.database.models import AIAnalysis, Administrator, AuditEvent, Incident, ResponseAction
from backend.database.session import get_session
from backend.services.audit import record_event

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

Severity = Literal["Low", "Medium", "High", "Critical"]
Status = Literal["open", "investigating", "resolved"]
StatusFilter = Literal["open", "investigating", "resolved", "active"]


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_code: str
    source_device_id: int | None
    source_ip: str
    target_ip: str
    risk_score: int | None
    severity: str | None
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    model: str
    status: str
    assessment: dict | None = Field(validation_alias="assessment_json")
    error_message: str | None
    requested_at: datetime
    completed_at: datetime | None


class IncidentDetail(IncidentOut):
    evidence: dict = Field(validation_alias="evidence_json")
    source_device: DeviceOut | None
    analyses: list[AnalysisOut] = []
    actions: list[ActionOut] = []


class StatusUpdate(BaseModel):
    status: Status
    note: str | None = Field(None, max_length=300)


class StatusCounts(BaseModel):
    open: int = 0
    investigating: int = 0
    resolved: int = 0


class HistoryEvent(BaseModel):
    id: int
    occurred_at: datetime
    event_type: str
    outcome: str
    actor: str | None
    response_action_id: int | None
    details: dict


def find_incident(session, incident_id):
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


def build_detail(session, incident):
    detail = IncidentDetail.model_validate(incident)
    analyses = session.scalars(
        select(AIAnalysis).where(AIAnalysis.incident_id == incident.id).order_by(AIAnalysis.requested_at.desc())
    ).all()
    actions = session.scalars(
        select(ResponseAction).where(ResponseAction.incident_id == incident.id).order_by(ResponseAction.created_at.desc())
    ).all()
    detail.analyses = [AnalysisOut.model_validate(analysis) for analysis in analyses]
    detail.actions = [ActionOut.model_validate(action) for action in actions]
    return detail


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    status: StatusFilter | None = None,
    severity: Severity | None = None,
    search: str | None = Query(None, max_length=50),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_device_id: int | None = Query(None, ge=1),
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    query = select(Incident)
    if status == "active":
        query = query.where(Incident.status != "resolved")
    elif status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if source_device_id is not None:
        query = query.where(Incident.source_device_id == source_device_id)
    if search and search.strip():
        text = "%" + search.strip().replace(" ", "_") + "%"
        query = query.where(or_(
            Incident.source_ip.ilike(text), Incident.target_ip.ilike(text), Incident.rule_code.ilike(text),
        ))
    query = query.order_by(Incident.created_at.desc(), Incident.id.desc()).offset(offset).limit(limit)
    return session.scalars(query).all()


@router.get("/counts", response_model=StatusCounts)
def count_incidents(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    rows = session.execute(select(Incident.status, func.count()).group_by(Incident.status)).tuples().all()
    return StatusCounts(**dict(rows))


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    return build_detail(session, find_incident(session, incident_id))


@router.get("/{incident_id}/history", response_model=list[HistoryEvent])
def incident_history(incident_id: int, session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    find_incident(session, incident_id)
    events = session.scalars(
        select(AuditEvent).where(AuditEvent.incident_id == incident_id).order_by(AuditEvent.occurred_at, AuditEvent.id)
    ).all()
    return [
        HistoryEvent(
            id=event.id,
            occurred_at=event.occurred_at,
            event_type=event.event_type,
            outcome=event.outcome,
            actor=event.administrator.username if event.administrator else None,
            response_action_id=event.response_action_id,
            details=event.details_json,
        )
        for event in events
    ]


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: int,
    data: StatusUpdate,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    incident = find_incident(session, incident_id)
    if incident.status == data.status:
        return build_detail(session, incident)

    details = {"from": incident.status, "to": data.status}
    if data.note and data.note.strip():
        details["note"] = data.note.strip()
    record_event(session, "incident.status_changed", admin=admin, incident_id=incident.id, details=details)
    incident.status = data.status
    incident.resolved_at = utc_now() if data.status == "resolved" else None
    session.commit()
    return build_detail(session, incident)