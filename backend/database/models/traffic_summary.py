"""Per-device windows, with directions measured from the device's perspective."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base


class TrafficSummary(Base):
    __tablename__ = "traffic_summaries"
    __table_args__ = (
        CheckConstraint("window_end > window_start", name="window_order"),
        *[CheckConstraint(f"typeof({field}) = 'integer' AND {field} >= 0", name=f"{field}_nonnegative")
          for field in ("bytes_sent", "bytes_received", "packets_sent", "packets_received", "connection_count")],
        UniqueConstraint("monitoring_run_id", "device_id", "window_start", name="uq_traffic_summaries_run_device_window"),
        Index("ix_traffic_summaries_device_id_window_start", "device_id", "window_start"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"))
    monitoring_run_id: Mapped[int] = mapped_column(ForeignKey("monitoring_runs.id", ondelete="RESTRICT"))
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime)
    bytes_sent: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    bytes_received: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    packets_sent: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    packets_received: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    connection_count: Mapped[int] = mapped_column(default=0, server_default=text("0"))

    device = relationship("Device")
    monitoring_run = relationship("MonitoringRun")
