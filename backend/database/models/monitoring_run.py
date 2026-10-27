"""Activation history; unfinished rows do not prove that a collector is alive."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, utc_now


class MonitoringRun(Base):
    __tablename__ = "monitoring_runs"
    __table_args__ = (
        CheckConstraint(
            "(ended_at IS NULL AND stop_reason IS NULL AND stopped_by_id IS NULL) OR "
            "(ended_at IS NOT NULL AND stop_reason IS NOT NULL AND ended_at >= started_at)",
            name="end_state",
        ),
        CheckConstraint("stop_reason IN ('administrator', 'shutdown', 'failure', 'interrupted')", name="stop_reason_values"),
        CheckConstraint(
            "(stop_reason = 'administrator' AND stopped_by_id IS NOT NULL) OR "
            "((stop_reason IS NULL OR stop_reason != 'administrator') AND stopped_by_id IS NULL)",
            name="stop_actor",
        ),
        # A constant key makes every unfinished run compete for the same slot.
        Index("uq_monitoring_runs_unfinished", text("(1)"), unique=True,
              sqlite_where=text("ended_at IS NULL")),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime)
    started_by_id: Mapped[int] = mapped_column(ForeignKey("administrators.id", ondelete="RESTRICT"), index=True)
    stopped_by_id: Mapped[int | None] = mapped_column(ForeignKey("administrators.id", ondelete="RESTRICT"), index=True)
    stop_reason: Mapped[str | None] = mapped_column(String(20))

    started_by = relationship("Administrator", foreign_keys=[started_by_id])
    stopped_by = relationship("Administrator", foreign_keys=[stopped_by_id])
