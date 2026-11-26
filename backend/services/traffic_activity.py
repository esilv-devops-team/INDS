"""Aggregate gateway observations into local per-device traffic summaries."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import case, func, or_, select, update
from sqlalchemy.dialects.sqlite import insert

from backend.database.base import utc_now
from backend.database.models import Device, MonitoringRun, TrafficSummary
from backend.services.statistics import WINDOWS, floor_time
from backend.services.vendor_lookup import normalize_mac

MINUTE = timedelta(minutes=1)
RATE_WINDOW = 5 * MINUTE


class Observation(BaseModel):
    timestamp: float = Field(allow_inf_nan=False)
    source_mac: str
    destination_mac: str
    captured_bytes: int = Field(strict=True, gt=0, le=2**32 - 1)

    @field_validator("source_mac", "destination_mac")
    @classmethod
    def canonical_mac(cls, value):
        return normalize_mac(value)


@dataclass
class Counters:
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0


def minute_start(moment):
    return moment.replace(second=0, microsecond=0)


class TrafficAccumulator:
    def __init__(self, devices, started_at):
        self.devices = devices
        self.started_at = started_at
        self.windows = {}
        self.last_seen = {}
        self.skipped = 0

    def add(self, observation):
        try:
            seen_at = datetime.fromtimestamp(observation.timestamp, UTC).replace(tzinfo=None)
        except (ValueError, OverflowError, OSError):
            self.skipped += 1
            return
        if seen_at < self.started_at or seen_at > utc_now():
            self.skipped += 1
            return
        window = minute_start(seen_at)
        for mac, outbound in ((observation.source_mac, True), (observation.destination_mac, False)):
            device_id = self.devices.get(mac.upper())
            if device_id is None:
                continue
            counters = self.windows.setdefault((device_id, window), Counters())
            if outbound:
                self.last_seen[device_id] = max(self.last_seen.get(device_id, seen_at), seen_at)
                counters.bytes_sent += observation.captured_bytes
                counters.packets_sent += 1
            else:
                counters.bytes_received += observation.captured_bytes
                counters.packets_received += 1


def summarize_observations(lines, devices, started_at):
    totals = TrafficAccumulator(devices, started_at)
    for line in lines:
        try:
            observation = Observation.model_validate_json(line)
        except ValidationError:
            totals.skipped += 1
            continue
        totals.add(observation)
    return totals.windows, totals.last_seen, totals.skipped


def persist_summaries(session, run_id, windows, last_seen):
    # The write lock serializes ingestion with a lifecycle change in SQLite.
    active = session.execute(
        update(MonitoringRun)
        .where(MonitoringRun.id == run_id, MonitoringRun.ended_at.is_(None))
        .values(id=MonitoringRun.id)
        .returning(MonitoringRun.id)
    ).scalar_one_or_none()
    if active is None:
        return False

    for (device_id, window), counters in windows.items():
        values = vars(counters)
        statement = insert(TrafficSummary).values(
            device_id=device_id, monitoring_run_id=run_id,
            window_start=window, window_end=window + MINUTE, **values,
        )
        session.execute(statement.on_conflict_do_update(
            index_elements=["monitoring_run_id", "device_id", "window_start"],
            set_={field: getattr(TrafficSummary, field) + value for field, value in values.items()},
        ))
    for device_id, seen_at in last_seen.items():
        session.execute(
            update(Device).where(Device.id == device_id,
                                 or_(Device.last_active_at.is_(None), Device.last_active_at < seen_at))
            .values(last_active_at=seen_at,
                    last_seen_at=case((Device.last_seen_at < seen_at, seen_at), else_=Device.last_seen_at))
        )
    return True


def device_rates(session, device_id):
    end = minute_start(utc_now())
    start = end - RATE_WINDOW
    sent, received = session.execute(
        select(
            func.coalesce(func.sum(TrafficSummary.bytes_sent), 0),
            func.coalesce(func.sum(TrafficSummary.bytes_received), 0),
        ).where(
            TrafficSummary.device_id == device_id,
            TrafficSummary.window_start >= start,
            TrafficSummary.window_start < end,
        )
    ).one()
    return {
        "window_start": start,
        "window_end": end,
        "upload_bps": sent * 8 / RATE_WINDOW.total_seconds(),
        "download_bps": received * 8 / RATE_WINDOW.total_seconds(),
    }


def device_traffic_history(session, device_id, window):
    length, size = WINDOWS[window]
    now = utc_now()
    start = floor_time(now, size) + size - length
    seconds = int(size.total_seconds())
    buckets = []
    for index in range(length // size):
        point = start + index * size
        buckets.append({
            "start": point,
            "seconds": max(1, min(seconds, (now - point).total_seconds())),
            "download": 0,
            "upload": 0,
            "packets": 0,
        })

    rows = session.execute(select(
        TrafficSummary.window_start,
        func.sum(TrafficSummary.bytes_received),
        func.sum(TrafficSummary.bytes_sent),
        func.sum(TrafficSummary.packets_received + TrafficSummary.packets_sent),
    ).where(
        TrafficSummary.device_id == device_id,
        TrafficSummary.window_start >= start,
        TrafficSummary.window_start <= now,
    ).group_by(TrafficSummary.window_start))
    for observed_at, received, sent, packets in rows:
        bucket = buckets[(observed_at - start) // size]
        bucket["download"] += received
        bucket["upload"] += sent
        bucket["packets"] += packets

    return {
        "window": window,
        "bucket_minutes": int(size / MINUTE),
        "buckets": buckets,
        "download": sum(bucket["download"] for bucket in buckets),
        "upload": sum(bucket["upload"] for bucket in buckets),
        "packets": sum(bucket["packets"] for bucket in buckets),
    }
