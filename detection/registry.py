"""Build the rule sets that monitoring can evaluate today."""

from detection.engine import DetectionEngine
from detection.rules.traffic_spike import TrafficSpikeRule, TrafficSpikeSettings, TrafficWindow


def traffic_rules(settings: TrafficSpikeSettings) -> DetectionEngine[TrafficWindow]:
    return DetectionEngine((TrafficSpikeRule(settings),))
