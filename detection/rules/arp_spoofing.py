"""Detect ARP claims that conflict with configured trusted bindings."""

from dataclasses import dataclass
from datetime import datetime

from detection.base import Finding, RuleInfo


@dataclass(frozen=True)
class ArpClaim:
    timestamp: datetime
    sender_ip: str
    sender_mac: str
    frame_source_mac: str
    operation: int
    source_device_id: int | None


class ArpSpoofingRule:
    def __init__(self, bindings: dict[str, str]):
        self.bindings = dict(bindings)
        self.info = RuleInfo(
            "ARP_SPOOFING", "An ARP claim conflicts with a protected IPv4 binding.",
            "High", bool(bindings), 300,
        )

    def evaluate(self, observation: ArpClaim) -> Finding | None:
        expected = self.bindings.get(observation.sender_ip)
        if observation.operation not in (1, 2) or expected is None:
            return None
        claimed = observation.sender_mac.upper()
        if claimed == expected:
            return None

        return Finding(
            rule_id=self.info.rule_id,
            source_device_id=observation.source_device_id,
            timestamp=observation.timestamp,
            severity=self.info.severity,
            evidence={"sender_ip": observation.sender_ip, "expected_mac": expected, "claimed_mac": claimed},
            measured={"arp_operation": observation.operation},
            source_mac=observation.frame_source_mac,
        )
