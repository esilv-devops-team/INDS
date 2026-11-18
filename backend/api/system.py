from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.base import utc_now
from backend.database.models import Administrator, Device, Incident, MonitoringRun
from backend.database.session import get_session

router = APIRouter(prefix="/api/system", tags=["system"])

ONLINE_MINUTES = 5


@router.get("/status")
def system_status(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    run = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
    online_since = utc_now() - timedelta(minutes=ONLINE_MINUTES)

    rows = session.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.status != "resolved")
        .group_by(Incident.severity)
    ).all()
    open_by_severity = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for severity, count in rows:
        if severity:
            open_by_severity[severity] = count

    return {
        "monitoring": "on" if run else "off",
        "monitoring_since": run.started_at if run else None,
        "devices": session.scalar(select(func.count(Device.id))),
        "online_devices": session.scalar(select(func.count(Device.id)).where(Device.last_seen_at >= online_since)),
        "last_device_seen_at": session.scalar(select(func.max(Device.last_seen_at))),
        "open_incidents": sum(open_by_severity.values()),
        "open_by_severity": open_by_severity,
    }