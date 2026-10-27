"""Administrator decisions and gateway execution state are independent."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.database.base import Base, utc_now
from backend.services.vendor_lookup import normalize_mac


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint("action_type IN ('block', 'rate_limit')", name="action_values"),
        CheckConstraint(
            "(action_type = 'block' AND rate_limit_kbps IS NULL) OR "
            "(action_type = 'rate_limit' AND rate_limit_kbps IS NOT NULL AND "
            "typeof(rate_limit_kbps) = 'integer' AND rate_limit_kbps > 0)", name="rate_limit",
        ),
        CheckConstraint("target_mac GLOB '" + ":".join(["[0-9A-F][0-9A-F]"] * 6) + "'", name="target_mac_format"),
        CheckConstraint("length(request_key) > 0 AND length(trim(reason)) > 0", name="request_details"),
        CheckConstraint("approval_status IN ('pending', 'approved', 'rejected', 'cancelled')", name="approval_values"),
        CheckConstraint(
            "(approval_status = 'pending' AND decided_by_id IS NULL AND decided_at IS NULL) OR "
            "(approval_status IN ('approved', 'rejected') AND decided_by_id IS NOT NULL AND decided_at IS NOT NULL) OR "
            "(approval_status = 'cancelled' AND decided_at IS NOT NULL)", name="decision_state",
        ),
        CheckConstraint("execution_status IN ('not_applied', 'applying', 'active', 'removing', 'removed', 'failed', 'unknown')", name="execution_values"),
        CheckConstraint("execution_status = 'not_applied' OR approval_status = 'approved'", name="execution_approved"),
        CheckConstraint("execution_status NOT IN ('active', 'removing', 'removed') OR applied_at IS NOT NULL", name="application_time"),
        CheckConstraint("(execution_status = 'removed' AND removed_at IS NOT NULL) OR (execution_status != 'removed' AND removed_at IS NULL)", name="removal_state"),
        CheckConstraint("updated_at >= created_at", name="update_order"),
        CheckConstraint("decided_at IS NULL OR decided_at >= created_at", name="decision_order"),
        CheckConstraint("applied_at IS NULL OR (decided_at IS NOT NULL AND applied_at >= decided_at)", name="application_order"),
        CheckConstraint("expires_at IS NULL OR (expires_at > created_at AND (applied_at IS NULL OR expires_at > applied_at))", name="expiry_order"),
        CheckConstraint("removed_at IS NULL OR removed_at >= applied_at", name="removal_order"),
        Index("ix_response_actions_approval_status_created_at", "approval_status", "created_at"),
        Index("ix_response_actions_execution_status_expires_at", "execution_status", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    ai_analysis_id: Mapped[int | None] = mapped_column(ForeignKey("ai_analyses.id", ondelete="RESTRICT"), index=True)
    request_key: Mapped[str] = mapped_column(String(100), unique=True)
    action_type: Mapped[str] = mapped_column(String(20))
    target_mac: Mapped[str] = mapped_column(String(17))
    target_ip: Mapped[str | None] = mapped_column(String(45))
    rate_limit_kbps: Mapped[int | None]
    reason: Mapped[str] = mapped_column(Text)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("administrators.id", ondelete="RESTRICT"), index=True)
    approval_status: Mapped[str] = mapped_column(String(20), default="pending", server_default=text("'pending'"))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("administrators.id", ondelete="RESTRICT"), index=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    execution_status: Mapped[str] = mapped_column(String(20), default="not_applied", server_default=text("'not_applied'"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, onupdate=utc_now)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime)
    error_message: Mapped[str | None] = mapped_column(Text)

    incident = relationship("Incident")
    device = relationship("Device")
    ai_analysis = relationship("AIAnalysis")
    requested_by = relationship("Administrator", foreign_keys=[requested_by_id])
    decided_by = relationship("Administrator", foreign_keys=[decided_by_id])

    @validates("target_mac")
    def normalize_target(self, _key, value):
        return normalize_mac(value)
