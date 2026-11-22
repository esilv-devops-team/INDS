"""Adapt gateway ARP metadata and protected bindings for detection."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from backend.services.vendor_lookup import normalize_mac
from detection.rules.arp_spoofing import ArpClaim


def parse_bindings(pairs):
    if not isinstance(pairs, dict):
        raise ValueError("Protected ARP bindings must map IPv4 addresses to MAC addresses.")
    bindings = {}
    for ip, mac in pairs.items():
        if not isinstance(ip, str) or not isinstance(mac, str):
            raise ValueError("Protected ARP bindings must map IPv4 addresses to MAC addresses.")
        address = IPv4Address(ip.strip())
        normalized = normalize_mac(mac)
        if address.is_unspecified or address.is_multicast or address == IPv4Address("255.255.255.255"):
            raise ValueError("Protected ARP bindings require an IPv4 host address.")
        if normalized == "00:00:00:00:00:00" or int(normalized[:2], 16) & 1:
            raise ValueError("Protected ARP bindings require a unicast MAC.")
        if str(address) in bindings:
            raise ValueError(f"Duplicate protected ARP address: {address}.")
        bindings[str(address)] = normalized
    return bindings


def evaluate_arp(engine, metadata, devices, started_at):
    if not engine.rules or getattr(metadata, "protocol", None) != "ARP":
        return []
    try:
        observed_at = datetime.fromtimestamp(metadata.timestamp, UTC)
        claimed_mac = normalize_mac(metadata.arp_sender_mac)
        frame_source = normalize_mac(metadata.source_mac)
    except (AttributeError, ValueError, OverflowError, OSError):
        return []
    if observed_at < started_at.replace(tzinfo=UTC):
        return []
    if any(mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1 for mac in (claimed_mac, frame_source)):
        return []
    return engine.evaluate(ArpClaim(
        observed_at, metadata.source_ip, claimed_mac, frame_source,
        metadata.arp_operation, devices.get(frame_source),
    ))
