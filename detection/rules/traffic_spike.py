"""Detect unusually high aggregate byte or packet rates."""

from dataclasses import dataclass
from datetime import datetime

from detection.base import Finding, RuleInfo, Severity


@dataclass(frozen=True)
class TrafficWindow:
    device_id: int
    start: datetime
    end: datetime
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int


@dataclass(frozen=True)
class TrafficSpikeSettings:
    window_minutes: int = 1
    max_bytes_per_minute: int = 100 * 1024**2
    max_packets_per_minute: int = 100_000
    enabled: bool = True
    cooldown_seconds: int = 300
    severity: Severity = "Medium"

    def __post_init__(self):
        if not 1 <= self.window_minutes <= 60:
            raise ValueError("Traffic spike window must be between 1 and 60 minutes.")
        if min(self.max_bytes_per_minute, self.max_packets_per_minute, self.cooldown_seconds) <= 0:
            raise ValueError("Traffic spike limits and cooldown must be positive.")
        if self.severity not in ("Low", "Medium", "High", "Critical"):
            raise ValueError("Traffic spike severity must be Low, Medium, High or Critical.")


class TrafficSpikeRule:
    def __init__(self, settings: TrafficSpikeSettings):
        self.settings = settings
        self.info = RuleInfo(
            rule_id="TRAFFIC_SPIKE",
            description="Per-device traffic exceeds a configured byte or packet rate.",
            severity=settings.severity,
            enabled=settings.enabled,
            cooldown_seconds=settings.cooldown_seconds,
        )

    def evaluate(self, observation: TrafficWindow) -> Finding | None:
        minutes = self.settings.window_minutes
        if (observation.end - observation.start).total_seconds() != minutes * 60:
            return None

        total_bytes = observation.bytes_sent + observation.bytes_received
        total_packets = observation.packets_sent + observation.packets_received
        byte_spike = total_bytes > self.settings.max_bytes_per_minute * minutes
        packet_spike = total_packets > self.settings.max_packets_per_minute * minutes
        if not (byte_spike or packet_spike):
            return None

        trigger = "bytes_and_packets" if byte_spike and packet_spike else "bytes" if byte_spike else "packets"
        return Finding(
            rule_id=self.info.rule_id,
            source_device_id=observation.device_id,
            timestamp=observation.end,
            severity=self.info.severity,
            evidence={
                "trigger": trigger,
                "window_start": observation.start.isoformat(),
                "window_end": observation.end.isoformat(),
                "bytes_per_minute_limit": self.settings.max_bytes_per_minute,
                "packets_per_minute_limit": self.settings.max_packets_per_minute,
            },
            measured={
                "bytes_sent": observation.bytes_sent,
                "bytes_received": observation.bytes_received,
                "packets_sent": observation.packets_sent,
                "packets_received": observation.packets_received,
                "bytes_per_minute": total_bytes / minutes,
                "packets_per_minute": total_packets / minutes,
            },
        )
