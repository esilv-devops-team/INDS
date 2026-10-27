"""One durable record per DeepSeek attempt, including retries."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, utc_now


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')", name="status_values"),
        CheckConstraint("json_valid(input_summary_json) AND json_type(input_summary_json) = 'object'", name="input_object"),
        CheckConstraint("assessment_json IS NULL OR (json_valid(assessment_json) AND json_type(assessment_json) = 'object')", name="assessment_object"),
        CheckConstraint(
            "(status IN ('pending', 'running') AND completed_at IS NULL) OR "
            "(status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)",
            name="completion_state",
        ),
        CheckConstraint("status != 'running' OR started_at IS NOT NULL", name="running_started"),
        CheckConstraint("status != 'succeeded' OR (started_at IS NOT NULL AND assessment_json IS NOT NULL)", name="success_result"),
        CheckConstraint("status != 'failed' OR (error_message IS NOT NULL AND length(error_message) > 0)", name="failure_error"),
        CheckConstraint("started_at IS NULL OR started_at >= requested_at", name="start_order"),
        CheckConstraint("completed_at IS NULL OR (completed_at >= requested_at AND (started_at IS NULL OR completed_at >= started_at))", name="completion_order"),
        Index("ix_ai_analyses_incident_id_requested_at", "incident_id", "requested_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    model: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pending", server_default=text("'pending'"))
    input_summary_json: Mapped[dict] = mapped_column(JSON(none_as_null=True))
    assessment_json: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    error_message: Mapped[str | None] = mapped_column(Text)

    incident = relationship("Incident")
