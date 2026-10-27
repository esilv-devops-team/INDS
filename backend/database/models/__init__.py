"""Register persistent models for Alembic metadata discovery."""

from backend.database.models.device import Device
from backend.database.models.incident import Incident
from backend.database.models.administrator import Administrator
from backend.database.models.monitoring_run import MonitoringRun
from backend.database.models.traffic_summary import TrafficSummary
from backend.database.models.ai_analysis import AIAnalysis
from backend.database.models.response_action import ResponseAction
from backend.database.models.audit_event import AuditEvent

__all__ = [
    "Administrator", "Device", "MonitoringRun", "Incident", "TrafficSummary",
    "AIAnalysis", "ResponseAction", "AuditEvent",
]
