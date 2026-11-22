"""Detect one device trying many different ports on the same target."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from detection.base import Finding, RuleInfo, Severity

MAX_TRACKED_PAIRS = 10000


@dataclass(frozen=True)
class PortProbe:
    timestamp: datetime
    source_ip: str
    target_ip: str
    port: int
    protocol: str
    source_mac: str
    source_device_id: int | None


@dataclass(frozen=True)
class PortScanSettings:
    distinct_ports: int = 20
    window_seconds: int = 60
    enabled: bool = True
    cooldown_seconds: int = 300
    severity: Severity = "Medium"

    def __post_init__(self):
        if self.distinct_ports < 2 or self.window_seconds < 1 or self.cooldown_seconds < 1:
            raise ValueError("Port scan needs at least 2 ports and a positive window and cooldown.")
        if self.severity not in ("Low", "Medium", "High", "Critical"):
            raise ValueError("Port scan severity must be Low, Medium, High or Critical.")


class PortScanRule:
    def __init__(self, settings: PortScanSettings):
        self.settings = settings
        self.info = RuleInfo(
            rule_id="PORT_SCAN",
            description="A device tries many different ports on the same target in a short time.",
            severity=settings.severity,
            enabled=settings.enabled,
            cooldown_seconds=settings.cooldown_seconds,
        )
        self.recent = {}

    def forget_old(self, oldest):
        self.recent = {
            pair: ports for pair, ports in self.recent.items() if max(ports.values()) >= oldest
        }

    def evaluate(self, observation: PortProbe) -> Finding | None:
        oldest = observation.timestamp - timedelta(seconds=self.settings.window_seconds)
        if len(self.recent) >= MAX_TRACKED_PAIRS:
            self.forget_old(oldest)

        pair = (observation.source_ip, observation.target_ip)
        ports = self.recent.setdefault(pair, {})
        ports[observation.port] = observation.timestamp
        for port, seen in list(ports.items()):
            if seen < oldest:
                del ports[port]

        if len(ports) < self.settings.distinct_ports:
            return None

        tried = sorted(ports)
        del self.recent[pair]
        return Finding(
            rule_id=self.info.rule_id,
            source_device_id=observation.source_device_id,
            timestamp=observation.timestamp,
            severity=self.info.severity,
            evidence={
                "source_ip": observation.source_ip,
                "target_ip": observation.target_ip,
                "protocol": observation.protocol,
                "window_seconds": self.settings.window_seconds,
                "distinct_ports_limit": self.settings.distinct_ports,
                "sample_ports": ",".join(str(port) for port in tried[:15]),
            },
            measured={"distinct_ports": len(tried)},
            source_mac=observation.source_mac,
        )