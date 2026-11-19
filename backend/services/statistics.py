from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import select

from backend.database.base import utc_now
from backend.database.models import Device, Incident, TrafficSummary

StatisticsWindow = Literal["1h", "24h", "7d"]

WINDOWS = {
    "1h": (timedelta(hours=1), timedelta(minutes=5)),
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "7d": (timedelta(days=7), timedelta(hours=6)),
}


def floor_time(moment, size):
    return moment - (moment - datetime(2000, 1, 1)) % size


def build_statistics(session, window):
    length, size = WINDOWS[window]
    now = utc_now()
    end = floor_time(now, size) + size
    start = end - length

    buckets = []
    for i in range(int(length / size)):
        buckets.append({
            "start": start + i * size,
            "seconds": int(size.total_seconds()),
            "download": 0,
            "upload": 0,
            "active_devices": 0,
            "new_devices": 0,
            "incidents": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        })

    buckets[-1]["seconds"] = max(60, int((now - buckets[-1]["start"]).total_seconds()))

    def bucket_for(moment):
        return buckets[int((moment - start) / size)]

    summaries = session.scalars(
        select(TrafficSummary).where(TrafficSummary.window_start >= start, TrafficSummary.window_start < end)
    ).all()
    active = [set() for _ in buckets]
    per_device = {}
    for summary in summaries:
        index = int((summary.window_start - start) / size)
        buckets[index]["download"] += summary.bytes_received
        buckets[index]["upload"] += summary.bytes_sent
        active[index].add(summary.device_id)
        totals = per_device.setdefault(summary.device_id, {"download": 0, "upload": 0})
        totals["download"] += summary.bytes_received
        totals["upload"] += summary.bytes_sent
    for bucket, devices in zip(buckets, active):
        bucket["active_devices"] = len(devices)

    new_devices = session.scalars(select(Device).where(Device.first_seen_at >= start, Device.first_seen_at < end)).all()
    for device in new_devices:
        bucket_for(device.first_seen_at)["new_devices"] += 1

    incidents = session.scalars(select(Incident).where(Incident.created_at >= start, Incident.created_at < end)).all()
    for incident in incidents:
        bucket = bucket_for(incident.created_at)
        bucket["incidents"] += 1
        if incident.severity:
            bucket[incident.severity.lower()] += 1

    top_devices = []
    for device_id, totals in per_device.items():
        device = session.get(Device, device_id)
        top_devices.append({
            "id": device_id,
            "name": device.hostname or device.mac_address,
            "ip": device.current_ip,
            "download": totals["download"],
            "upload": totals["upload"],
            "total": totals["download"] + totals["upload"],
        })
    top_devices.sort(key=lambda item: item["total"], reverse=True)

    return {
        "window": window,
        "bucket_minutes": int(size.total_seconds() // 60),
        "start": start,
        "end": end,
        "buckets": buckets,
        "totals": {
            "download": sum(bucket["download"] for bucket in buckets),
            "upload": sum(bucket["upload"] for bucket in buckets),
            "active_devices": len(per_device),
            "new_devices": len(new_devices),
            "incidents": len(incidents),
        },
        "top_devices": top_devices[:5],
    }
