from datetime import timedelta
from uuid import uuid4

from backend.database.base import utc_now
from backend.database.models import ResponseAction
from backend.services.response_execution import open_block_exists, reserve_response_write, response_event
from backend.services.response_policy import assess_response

SUPPORTED_ACTIONS = ("block", "monitor")
TEMPORARY_BLOCK_MINUTES = 15
MAX_REASON = 300


def policy_refusal(policy, incident):
    if incident.status == "resolved":
        return "the incident is already resolved"
    if policy["risk"] not in ("HIGH", "CRITICAL"):
        return f"the policy only blocks High or Critical incidents (this one is {policy['risk'].capitalize()})"
    extra = policy["reasons"][2:]
    return extra[0] if extra else "the response policy does not allow it"


def propose_response(session, analysis, assessment):
    result = dict(assessment)
    wanted = result.get("recommended_action")
    if wanted not in SUPPORTED_ACTIONS:
        result["recommended_action"] = "monitor"
        result["response_note"] = f'INDS does not support "{wanted}", it was saved as monitor.'
        return result
    if wanted == "monitor":
        result["response_note"] = "No action proposed, INDS keeps monitoring the device."
        return result

    incident = analysis.incident
    policy = assess_response(incident)
    if not policy["approval_required"]:
        result["response_note"] = "Block not proposed: " + policy_refusal(policy, incident) + "."
        return result

    device = incident.source_device
    reserve_response_write(session)
    if open_block_exists(session, device.mac_address):
        result["response_note"] = "Block not proposed: a block for this device is already pending or active."
        return result

    now = utc_now()
    minutes = TEMPORARY_BLOCK_MINUTES if policy["recommendation"] == "temporary_block" else None
    action = ResponseAction(
        incident_id=incident.id,
        device_id=device.id,
        ai_analysis_id=analysis.id,
        action_type="block",
        target_mac=device.mac_address,
        target_ip=device.reported_ip,
        reason=("AI: " + result["justification"])[:MAX_REASON],
        request_key=uuid4().hex,
        created_at=now,
        expires_at=now + timedelta(minutes=minutes) if minutes else None,
    )
    session.add(action)
    session.flush()
    response_event(session, action, "proposed")
    result["response_note"] = "Block proposed, waiting for the administrator."
    if minutes:
        result["response_note"] = f"Temporary block ({minutes} min) proposed, waiting for the administrator."
    return result
