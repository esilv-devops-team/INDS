"""Structured operational history; append-only behavior belongs to services."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, utc_now


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("actor_type IN ('administrator', 'system')", name="actor_values"),
        CheckConstraint(
            "(actor_type = 'administrator' AND administrator_id IS NOT NULL) OR "
            "(actor_type = 'system' AND administrator_id IS NULL)", name="actor_identity",
        ),
        CheckConstraint("outcome IN ('success', 'failure')", name="outcome_values"),
        CheckConstraint("length(trim(event_type)) > 0", name="event_type_present"),
        CheckConstraint("json_valid(details_json) AND json_type(details_json) = 'object'", name="details_object"),
        Index("ix_audit_events_event_type_occurred_at", "event_type", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    actor_type: Mapped[str] = mapped_column(String(20))
    administrator_id: Mapped[int | None] = mapped_column(ForeignKey("administrators.id", ondelete="RESTRICT"), index=True)
    event_type: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(10))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    monitoring_run_id: Mapped[int | None] = mapped_column(ForeignKey("monitoring_runs.id", ondelete="SET NULL"), index=True)
    ai_analysis_id: Mapped[int | None] = mapped_column(ForeignKey("ai_analyses.id", ondelete="SET NULL"), index=True)
    response_action_id: Mapped[int | None] = mapped_column(ForeignKey("response_actions.id", ondelete="SET NULL"), index=True)
    details_json: Mapped[dict] = mapped_column(JSON(none_as_null=True), default=dict)

    administrator = relationship("Administrator")
    device = relationship("Device")
    incident = relationship("Incident")
    monitoring_run = relationship("MonitoringRun")
    ai_analysis = relationship("AIAnalysis")
    response_action = relationship("ResponseAction")
