"""Local findings with historical address and severity snapshots."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, utc_now

if TYPE_CHECKING:
    from backend.database.models.device import Device


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name="severity_values"),
        CheckConstraint("status IN ('open', 'investigating', 'resolved')", name="status_values"),
        CheckConstraint("last_seen_at >= first_seen_at", name="observation_order"),
        CheckConstraint("updated_at >= created_at", name="update_order"),
        CheckConstraint(
            "(status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at >= created_at) "
            "OR (status != 'resolved' AND resolved_at IS NULL)", name="resolution_state"
        ),
        Index("ix_incidents_status_created_at", "status", "created_at"),
        Index("ix_incidents_source_device_id_created_at", "source_device_id", "created_at"),
        CheckConstraint("json_valid(evidence_json) AND json_type(evidence_json) = 'object'", name="evidence_object"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    monitoring_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitoring_runs.id", ondelete="RESTRICT"), index=True
    )
    rule_code: Mapped[str] = mapped_column(String(100))
    source_ip: Mapped[str] = mapped_column(String(45))
    target_ip: Mapped[str] = mapped_column(String(45))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    risk_score: Mapped[int | None]
    severity: Mapped[str | None] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20), default="open", server_default=text("'open'"))
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, onupdate=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)

    source_device: Mapped["Device | None"] = relationship(back_populates="incidents")
    monitoring_run = relationship("MonitoringRun")
