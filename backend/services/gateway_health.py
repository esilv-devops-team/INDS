import os
import platform
import time

import psutil
from sqlalchemy import func, select, text

from backend.database.base import utc_now
from backend.database.models import Device, MonitoringRun

BRIDGE_NAME = os.environ.get("INDS_BRIDGE", "br-inds")
IGNORED_PREFIXES = ("lo", "utun", "awdl", "llw", "anpi", "gif", "stf", "ap", "docker", "veth")
DISCOVERY_TIMEOUT_SECONDS = 120

last_counters = {}
psutil.cpu_percent(interval=None)


def read_temperature():
    if not hasattr(psutil, "sensors_temperatures"):
        return None
    for entries in psutil.sensors_temperatures().values():
        if entries:
            return round(entries[0].current, 1)
    return None


def read_system():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "hostname": platform.node(),
        "platform": platform.system() + " " + platform.release(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_count": psutil.cpu_count(),
        "load_average": [round(value, 2) for value in psutil.getloadavg()],
        "memory": {"used": memory.total - memory.available, "total": memory.total, "percent": memory.percent},
        "disk": {"used": disk.used, "total": disk.total, "percent": disk.percent},
        "temperature": read_temperature(),
    }


def read_interfaces():
    now = time.monotonic()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    interfaces = []

    for name, stat in stats.items():
        if name.startswith(IGNORED_PREFIXES) or name not in counters:
            continue

        count = counters[name]
        rx_rate = None
        tx_rate = None
        previous = last_counters.get(name)
        if previous and now > previous["time"]:
            seconds = now - previous["time"]
            rx_rate = max(0, (count.bytes_recv - previous["rx"]) / seconds)
            tx_rate = max(0, (count.bytes_sent - previous["tx"]) / seconds)
        last_counters[name] = {"time": now, "rx": count.bytes_recv, "tx": count.bytes_sent}

        interfaces.append({
            "name": name,
            "is_up": stat.isup,
            "is_bridge": name == BRIDGE_NAME,
            "speed_mbps": stat.speed or None,
            "rx_bytes": count.bytes_recv,
            "tx_bytes": count.bytes_sent,
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
        })

    interfaces.sort(key=lambda item: (not item["is_bridge"], not item["is_up"], item["name"]))
    return interfaces


def check_services(session, interfaces):
    services = []

    try:
        session.execute(text("SELECT 1"))
        services.append({"name": "Database", "state": "ok", "detail": "SQLite answers queries"})
    except Exception:
        services.append({"name": "Database", "state": "down", "detail": "SQLite does not answer"})
        return services

    last_report = session.scalar(select(func.max(Device.last_seen_at)))
    if last_report is None:
        services.append({"name": "Discovery sniffer", "state": "down", "detail": "never sent a report"})
    else:
        seconds = int((utc_now() - last_report).total_seconds())
        if seconds <= DISCOVERY_TIMEOUT_SECONDS:
            services.append({"name": "Discovery sniffer", "state": "ok", "detail": f"last report {seconds} s ago"})
        else:
            services.append({"name": "Discovery sniffer", "state": "down", "detail": f"no report for {seconds // 60} min"})

    bridge = [item for item in interfaces if item["is_bridge"]]
    if not bridge:
        services.append({"name": "Bridge " + BRIDGE_NAME, "state": "down", "detail": "interface not found on this machine"})
    elif bridge[0]["is_up"]:
        services.append({"name": "Bridge " + BRIDGE_NAME, "state": "ok", "detail": "forwarding interface is up"})
    else:
        services.append({"name": "Bridge " + BRIDGE_NAME, "state": "down", "detail": "interface is down"})

    run = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
    if run:
        services.append({"name": "Monitoring", "state": "ok", "detail": "running"})
    else:
        services.append({"name": "Monitoring", "state": "warn", "detail": "turned off"})

    return services


def collect_health(session):
    interfaces = read_interfaces()
    return {
        "system": read_system(),
        "interfaces": interfaces,
        "services": check_services(session, interfaces),
    }