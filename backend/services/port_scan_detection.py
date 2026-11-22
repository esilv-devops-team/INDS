"""Turn captured TCP and UDP packets into port probes for the port scan rule."""

from datetime import UTC, datetime

from backend.services.vendor_lookup import normalize_mac
from detection.rules.port_scan import PortProbe


def is_connection_attempt(metadata):
    if metadata.protocol == "TCP":
        flags = metadata.tcp_flags or ""
        return "S" in flags and "A" not in flags
    return metadata.protocol == "UDP"


def evaluate_port_scan(engine, metadata, devices, started_at):
    if not engine.rules or getattr(metadata, "protocol", None) not in ("TCP", "UDP"):
        return []
    if metadata.destination_port is None or not is_connection_attempt(metadata):
        return []
    try:
        observed_at = datetime.fromtimestamp(metadata.timestamp, UTC)
        source_mac = normalize_mac(metadata.source_mac)
    except (AttributeError, ValueError, OverflowError, OSError):
        return []
    if observed_at < started_at.replace(tzinfo=UTC):
        return []

    device_id = devices.get(source_mac)
    if metadata.protocol == "UDP" and device_id is None:
        return []

    return engine.evaluate(PortProbe(
        observed_at, metadata.source_ip, metadata.destination_ip, metadata.destination_port,
        metadata.protocol, source_mac, device_id,
    ))