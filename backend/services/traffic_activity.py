"""Aggregate gateway observations into local per-device traffic summaries."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.dialects.sqlite import insert

from backend.database.base import utc_now
from backend.database.models import Device, MonitoringRun, TrafficSummary
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


def summarize_observations(lines, devices, started_at):
    windows = {}
    last_seen = {}
    skipped = 0
    for line in lines:
        try:
            observation = Observation.model_validate_json(line)
            seen_at = datetime.fromtimestamp(observation.timestamp, UTC).replace(tzinfo=None)
        except (ValidationError, ValueError, OverflowError, OSError):
            skipped += 1
            continue
        if seen_at < started_at or seen_at > utc_now():
            skipped += 1
            continue

        window = minute_start(seen_at)
        for mac, outbound in ((observation.source_mac, True), (observation.destination_mac, False)):
            device_id = devices.get(mac)
            if device_id is None:
                continue
            last_seen[device_id] = max(last_seen.get(device_id, seen_at), seen_at)
            counters = windows.setdefault((device_id, window), Counters())
            if outbound:
                counters.bytes_sent += observation.captured_bytes
                counters.packets_sent += 1
            else:
                counters.bytes_received += observation.captured_bytes
                counters.packets_received += 1
    return windows, last_seen, skipped


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
            update(Device).where(Device.id == device_id, Device.last_seen_at < seen_at)
            .values(last_seen_at=seen_at)
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
