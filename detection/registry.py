"""Build the rule sets that monitoring can evaluate today."""

from detection.engine import DetectionEngine
from detection.rules.arp_spoofing import ArpClaim, ArpSpoofingRule
from detection.rules.port_scan import PortProbe, PortScanRule, PortScanSettings
from detection.rules.traffic_spike import TrafficSpikeRule, TrafficSpikeSettings, TrafficWindow


def traffic_rules(settings: TrafficSpikeSettings) -> DetectionEngine[TrafficWindow]:
    return DetectionEngine((TrafficSpikeRule(settings),))


def arp_rules(bindings: dict[str, str], severity="High", cooldown_seconds=300, enabled=True) -> DetectionEngine[ArpClaim]:
    return DetectionEngine((ArpSpoofingRule(bindings, severity, cooldown_seconds, enabled),))


def port_scan_rules(settings: PortScanSettings) -> DetectionEngine[PortProbe]:
    return DetectionEngine((PortScanRule(settings),))