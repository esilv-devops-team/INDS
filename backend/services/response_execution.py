"""Validate approved block targets and reconcile the recorded gateway state."""

import logging
import os
import subprocess

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, ResponseAction
from backend.services.audit import record_event
from backend.services.vendor_lookup import normalize_mac
from gateway import firewall

logger = logging.getLogger(__name__)
GATEWAY_ERRORS = (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError)
OUTSTANDING = ("applying", "active", "removing", "unknown")


class ResponseError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def enforcement_enabled():
    return os.environ.get("INDS_FIREWALL_ENABLED") == "1"


def reserve_response_write(session):
    # SQLite cannot promote an older read snapshot after a concurrent capture write.
    session.connection().exec_driver_sql("UPDATE response_actions SET id = id WHERE 0")


def validate_block(session, action, guest_port):
    from gateway.discovery import macs_on_port

    if action.expires_at is not None:
        raise ResponseError(409, "Timed blocks require a gateway expiry policy.")
    device = session.get(Device, action.device_id) if action.device_id is not None else None
    if device is None or device.mac_address != action.target_mac or device.is_trusted:
        raise ResponseError(409, "Blocking requires a matching, untrusted inventory device.")
    try:
        ap_mac = normalize_mac(os.environ.get("INDS_MONITOR_AP_MAC", ""))
        if ap_mac == "00:00:00:00:00:00" or int(ap_mac[:2], 16) & 1 or not guest_port:
            raise ValueError("Missing valid guest network configuration.")
        guests = macs_on_port(guest_port)
    except GATEWAY_ERRORS as error:
        logger.exception("Unable to verify the intended block target")
        raise ResponseError(503, "Unable to verify the target on the guest bridge port.") from error
    if action.target_mac == ap_mac or action.target_mac not in guests:
        raise ResponseError(409, "The target is protected or was not learned on the guest bridge port.")
    existing = session.scalar(select(ResponseAction.id).where(
        ResponseAction.id != action.id,
        ResponseAction.target_mac == action.target_mac,
        ResponseAction.action_type == "block",
        ResponseAction.execution_status.in_(OUTSTANDING),
    ).limit(1))
    if existing is not None:
        raise ResponseError(409, "A block for this device already requires attention.")


def response_event(session, action, event, admin=None, *, outcome="success"):
    record_event(
        session, "response_action." + event, admin=admin, outcome=outcome,
        response_action_id=action.id, incident_id=action.incident_id, device_id=action.device_id,
        details={"action_type": action.action_type, "target_mac": action.target_mac},
    )


def mark_cleared(session, action, admin=None):
    action.error_message = None
    if action.applied_at is not None:
        action.execution_status = "removed"
        action.removed_at = max(utc_now(), action.applied_at)
    else:
        action.execution_status = "not_applied"
    response_event(session, action, "cleared", admin)


def execute_block(session, action, admin, *, blocked):
    event = "apply" if blocked else "reverse"
    mac, action_id = action.target_mac, action.id
    session.rollback()
    try:
        firewall.set_block(mac, blocked)
    except GATEWAY_ERRORS:
        logger.exception("Gateway failed to confirm response action %s", action_id)
        confirmed = False
    else:
        confirmed = True

    reserve_response_write(session)
    session.refresh(admin)
    session.refresh(action)
    if not confirmed:
        action.execution_status = "unknown"
        action.error_message = f"Gateway could not confirm the {event} operation."
        response_event(session, action, event + "_unconfirmed", admin, outcome="failure")
    elif blocked:
        action.execution_status = "active"
        action.applied_at = max(utc_now(), action.decided_at)
        action.error_message = None
        response_event(session, action, "applied", admin)
    else:
        mark_cleared(session, action, admin)
    session.commit()


def reconcile_blocks(engine, admin=None):
    if not enforcement_enabled():
        return
    try:
        firewall.clear_blocks()
    except GATEWAY_ERRORS:
        logger.exception("Unable to reconcile the INDS block set")
        error = True
    else:
        error = False
    with Session(engine) as session, session.begin():
        reserve_response_write(session)
        actions = session.scalars(select(ResponseAction).where(
            ResponseAction.action_type == "block", ResponseAction.execution_status.in_(OUTSTANDING),
        )).all()
        if error:
            for action in actions:
                action.execution_status = "unknown"
                action.error_message = "Gateway could not verify firewall cleanup."
                response_event(session, action, "cleanup_unconfirmed", admin, outcome="failure")
        else:
            for action in actions:
                mark_cleared(session, action, admin)
    if error:
        raise ResponseError(503, "Unable to verify gateway firewall cleanup.")
