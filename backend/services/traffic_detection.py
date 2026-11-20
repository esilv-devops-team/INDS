"""Feed completed monitoring windows to the detection engine."""

from datetime import UTC, timedelta
import os

from sqlalchemy import func, select

from backend.database.models import TrafficSummary
from backend.services.statistics import floor_time
from detection.registry import traffic_rules
from detection.rules.traffic_spike import TrafficSpikeSettings, TrafficWindow


def load_traffic_settings():
    defaults = TrafficSpikeSettings()
    enabled = os.environ.get("INDS_TRAFFIC_SPIKE_ENABLED", "1")
    if enabled not in {"0", "1"}:
        raise ValueError("INDS_TRAFFIC_SPIKE_ENABLED must be 0 or 1.")
    return TrafficSpikeSettings(
        enabled=enabled == "1",
        window_minutes=int(os.environ.get("INDS_TRAFFIC_SPIKE_WINDOW_MINUTES", defaults.window_minutes)),
        max_bytes_per_minute=int(os.environ.get("INDS_TRAFFIC_SPIKE_BYTES_PER_MINUTE", defaults.max_bytes_per_minute)),
        max_packets_per_minute=int(os.environ.get("INDS_TRAFFIC_SPIKE_PACKETS_PER_MINUTE", defaults.max_packets_per_minute)),
        cooldown_seconds=int(os.environ.get("INDS_TRAFFIC_SPIKE_COOLDOWN_SECONDS", defaults.cooldown_seconds)),
    )


class TrafficDetection:
    def __init__(self, settings, started_at):
        self.engine = traffic_rules(settings)
        self.size = timedelta(minutes=settings.window_minutes)
        aligned = floor_time(started_at, self.size)
        self.start = aligned if aligned == started_at else aligned + self.size

    def evaluate_ready(self, session, run_id, now):
        findings = []
        while self.engine.rules and self.start + self.size <= now:
            end = self.start + self.size
            rows = session.execute(
                select(
                    TrafficSummary.device_id,
                    func.sum(TrafficSummary.bytes_sent),
                    func.sum(TrafficSummary.bytes_received),
                    func.sum(TrafficSummary.packets_sent),
                    func.sum(TrafficSummary.packets_received),
                )
                .where(
                    TrafficSummary.monitoring_run_id == run_id,
                    TrafficSummary.window_start >= self.start,
                    TrafficSummary.window_start < end,
                    TrafficSummary.window_end <= end,
                )
                .group_by(TrafficSummary.device_id)
            ).all()
            start_utc, end_utc = self.start.replace(tzinfo=UTC), end.replace(tzinfo=UTC)
            for device_id, sent, received, packets_sent, packets_received in rows:
                window = TrafficWindow(device_id, start_utc, end_utc, sent, received, packets_sent, packets_received)
                findings.extend(self.engine.evaluate(window))
            self.start = end
        return findings
