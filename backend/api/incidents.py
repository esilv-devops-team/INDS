from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.api.devices import DeviceOut
from backend.database.base import utc_now
from backend.database.models import Administrator, Incident
from backend.database.session import get_session
from backend.services.audit import record_event

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

Severity = Literal["Low", "Medium", "High", "Critical"]
Status = Literal["open", "investigating", "resolved"]


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


class IncidentDetail(IncidentOut):
    evidence: dict = Field(validation_alias="evidence_json")
    source_device: DeviceOut | None


class StatusUpdate(BaseModel):
    status: Status


def find_incident(session, incident_id):
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    status: Status | None = None,
    severity: Severity | None = None,
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    query = query.order_by(Incident.created_at.desc()).limit(limit)
    return session.scalars(query).all()


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    return find_incident(session, incident_id)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: int,
    data: StatusUpdate,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    incident = find_incident(session, incident_id)
    if incident.status == data.status:
        return incident

    record_event(
        session, "incident.status_changed", admin=admin, incident_id=incident.id,
        details={"from": incident.status, "to": data.status},
    )
    incident.status = data.status
    incident.resolved_at = utc_now() if data.status == "resolved" else None
    session.commit()
    return incident