from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.base import utc_now
from backend.database.models import Administrator, MonitoringRun, ResponseAction
from backend.database.session import get_session
from backend.services.audit import record_event

router = APIRouter(prefix="/api/actions", tags=["actions"])


class AdminName(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    action_type: str
    target_mac: str
    target_ip: str | None
    rate_limit_kbps: int | None
    reason: str
    approval_status: str
    decided_by: AdminName | None
    decided_at: datetime | None
    execution_status: str
    error_message: str | None
    created_at: datetime


class Decision(BaseModel):
    decision: Literal["approved", "rejected"]


@router.post("/{action_id}/decision", response_model=ActionOut)
def decide_action(
    action_id: int,
    data: Decision,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="response action not found")
    if action.approval_status != "pending":
        raise HTTPException(status_code=409, detail="this action is already " + action.approval_status)

    if data.decision == "approved":
        running = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
        if running is None:
            raise HTTPException(status_code=409, detail="turn monitoring on before approving a response")

    action.approval_status = data.decision
    action.decided_by_id = admin.id
    action.decided_at = utc_now()
    record_event(
        session, "response_action." + data.decision, admin=admin,
        response_action_id=action.id, incident_id=action.incident_id, device_id=action.device_id,
        details={"action_type": action.action_type, "target_mac": action.target_mac},
    )
    session.commit()
    return action