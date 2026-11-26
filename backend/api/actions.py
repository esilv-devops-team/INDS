from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from backend.api.auth import get_current_admin
from backend.database.base import utc_now
from backend.database.models import Administrator, Incident, MonitoringRun, ResponseAction
from backend.database.session import get_session
from backend.services.monitoring import configured_interface
from backend.services.response_execution import (
    OUTSTANDING, ResponseError, enforcement_enabled, execute_block, open_block_exists,
    reserve_response_write, response_event, validate_block,
)
from backend.services.response_policy import assess_response

router = APIRouter(prefix="/api/actions", tags=["actions"])

ApprovalStatus = Literal["pending", "approved", "rejected", "cancelled"]
ExecutionStatus = Literal["not_applied", "applying", "active", "removing", "removed", "failed", "unknown"]


class AdminName(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    device_id: int | None
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
    updated_at: datetime
    applied_at: datetime | None
    expires_at: datetime | None
    removed_at: datetime | None


class Decision(BaseModel):
    decision: Literal["approved", "rejected"]


class Proposal(BaseModel):
    incident_id: int = Field(gt=0)
    reason: str = Field(min_length=1, max_length=300)
    duration_minutes: int | None = Field(default=None, ge=1, le=60)


@router.post("", response_model=ActionOut, status_code=201)
def propose_action(data: Proposal, request: Request,
                   session: Session = Depends(get_session),
                   admin: Administrator = Depends(get_current_admin)):
    with request.app.state.monitoring.lock:
        session.rollback()
        reserve_response_write(session)
        incident = session.get(Incident, data.incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        policy = assess_response(incident)
        if not policy["approval_required"]:
            raise HTTPException(status_code=409, detail="Incident policy does not permit a block proposal.")
        if not data.reason.strip():
            raise HTTPException(status_code=422, detail="Provide a response reason.")
        device = incident.source_device
        if open_block_exists(session, device.mac_address):
            raise HTTPException(status_code=409, detail="A block for this device already requires attention.")
        duration = data.duration_minutes or (15 if policy["recommendation"] == "temporary_block" else None)
        now = utc_now()
        action = ResponseAction(
            incident_id=incident.id, device_id=device.id, action_type="block",
            target_mac=device.mac_address, target_ip=device.reported_ip, reason=data.reason.strip(),
            requested_by_id=admin.id, request_key=uuid4().hex, created_at=now,
            expires_at=now + timedelta(minutes=duration) if duration else None,
        )
        session.add(action)
        session.flush()
        response_event(session, action, "proposed", admin)
        session.commit()
        return action


@router.get("", response_model=list[ActionOut])
def list_actions(
    approval: ApprovalStatus | None = None,
    execution: ExecutionStatus | None = None,
    device_id: int | None = Query(None, ge=1),
    limit: int = Query(21, ge=1, le=101),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    query = select(ResponseAction).options(joinedload(ResponseAction.decided_by))
    if approval is not None:
        query = query.where(ResponseAction.approval_status == approval)
    if execution is not None:
        query = query.where(ResponseAction.execution_status == execution)
    if device_id is not None:
        query = query.where(ResponseAction.device_id == device_id)
    query = query.order_by(ResponseAction.created_at.desc(), ResponseAction.id.desc()).offset(offset).limit(limit)
    return session.scalars(query).all()


@router.post("/{action_id}/decision", response_model=ActionOut)
def decide_action(
    action_id: int,
    data: Decision,
    request: Request,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    with request.app.state.monitoring.lock:
        session.rollback()
        reserve_response_write(session)
        return record_decision(session, admin, action_id, data.decision)


def record_decision(session, admin, action_id, decision):
    admin_id = admin.id
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="response action not found")
    if action.approval_status != "pending":
        raise HTTPException(status_code=409, detail="this action is already " + action.approval_status)

    apply = decision == "approved" and action.action_type == "block" and enforcement_enabled()
    decided_at = utc_now()
    if decision == "approved":
        if action.expires_at is not None and action.expires_at <= decided_at:
            raise HTTPException(status_code=409, detail="This response proposal has expired.")
        if action.requested_by_id is not None and action.incident is not None:
            if not assess_response(action.incident)["approval_required"]:
                raise HTTPException(status_code=409, detail="Incident policy no longer permits this response.")
        running = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
        if running is None:
            raise HTTPException(status_code=409, detail="turn monitoring on before approving a response")
    if apply:
        try:
            validate_block(session, action, configured_interface())
        except ResponseError as error:
            raise HTTPException(status_code=error.status, detail=str(error)) from error

    action.approval_status = decision
    action.decided_by_id = admin_id
    action.decided_at = decided_at
    if apply:
        action.execution_status = "applying"
    response_event(session, action, decision, admin)
    session.commit()
    if apply:
        execute_block(session, action, admin, blocked=True)
    return action


@router.post("/{action_id}/reverse", response_model=ActionOut)
def reverse_action(
    action_id: int,
    request: Request,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    if not enforcement_enabled():
        raise HTTPException(status_code=503, detail="gateway firewall enforcement is disabled")
    with request.app.state.monitoring.lock:
        session.rollback()
        reserve_response_write(session)
        session.refresh(admin)
        action = session.get(ResponseAction, action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="response action not found")
        if action.action_type != "block" or action.approval_status != "approved":
            raise HTTPException(status_code=409, detail="only approved blocks can be reversed")
        if action.execution_status not in OUTSTANDING:
            return action
        if action.applied_at is not None:
            action.execution_status = "removing"
        response_event(session, action, "reversal_requested", admin)
        session.commit()
        execute_block(session, action, admin, blocked=False)
        return action
