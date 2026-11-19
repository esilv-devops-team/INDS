from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.base import utc_now
from backend.database.models import Administrator, Device, Incident, MonitoringRun
from backend.database.session import get_session
from backend.services.monitoring import MonitoringError

router = APIRouter(prefix="/api/system", tags=["system"])

ONLINE_MINUTES = 5


@router.post("/monitoring/{command}", status_code=204)
def set_monitoring(
    command: str,
    request: Request,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    controller = request.app.state.monitoring
    try:
        if command == "start":
            controller.start(session.get_bind(), admin)
        elif command == "stop":
            controller.stop(session.get_bind(), admin=admin)
        else:
            raise HTTPException(status_code=404, detail="unknown monitoring command")
    except MonitoringError as error:
        raise HTTPException(status_code=error.status, detail=str(error)) from error


@router.get("/status")
def system_status(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    run = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
    stop_reason = None if run else session.scalar(
        select(MonitoringRun.stop_reason)
        .where(MonitoringRun.ended_at.is_not(None))
        .order_by(MonitoringRun.ended_at.desc(), MonitoringRun.id.desc())
        .limit(1)
    )
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
        "monitoring_stop_reason": stop_reason,
        "devices": session.scalar(select(func.count(Device.id))),
        "online_devices": session.scalar(select(func.count(Device.id)).where(Device.last_seen_at >= online_since)),
        "last_device_seen_at": session.scalar(select(func.max(Device.last_seen_at))),
        "open_incidents": sum(count for _, count in rows),
        "open_by_severity": open_by_severity,
    }
