"""Translate existing incident scores into advisory, operator-approved responses."""

import os

from backend.services.vendor_lookup import normalize_mac


def protected_macs():
    values = [os.environ.get("INDS_MONITOR_AP_MAC", ""), *os.environ.get("INDS_PROTECTED_MACS", "").split(",")]
    return {normalize_mac(value.strip()) for value in values if value.strip()}


def assess_response(incident):
    device = incident.source_device
    evidence = incident.evidence_json
    risk = (incident.severity or "Low").upper()
    confirmed = bool(device and device.reported_ip and device.ip_source in ("dhcp_lease", "neighbor"))
    try:
        protected = bool(device and (device.is_trusted or device.mac_address in protected_macs()))
    except ValueError:
        protected = True
    enabled = os.environ.get("INDS_ALLOW_BLOCK_PROPOSALS", "1") == "1"
    eligible = enabled and confirmed and not protected and incident.status != "resolved" and risk in ("HIGH", "CRITICAL")
    response = "observe" if risk == "LOW" else "alert"
    if eligible:
        response = "temporary_block" if risk == "CRITICAL" else "block"
    reasons = [f"Incident risk is {risk}", f"{evidence.get('occurrences', 1)} observed finding(s)"]
    if not confirmed:
        reasons.append("Current LAN address ownership is unconfirmed")
    if protected:
        reasons.append("Device is protected or protection settings are invalid")
    if not enabled:
        reasons.append("Block proposals are disabled by policy")
    return {
        "rule_severity": evidence.get("rule_severity"),
        "risk": risk,
        "confidence": "confirmed_address" if confirmed else "unconfirmed_address",
        "recommendation": response,
        "approval_required": eligible,
        "reasons": reasons,
    }
