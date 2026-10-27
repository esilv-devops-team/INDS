"""Observed device identities, not guaranteed physical-device identities."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.database.base import Base, utc_now
from backend.services.vendor_lookup import normalize_mac

if TYPE_CHECKING:
    from backend.database.models.incident import Incident


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("last_seen_at >= first_seen_at", name="observation_order"),
        CheckConstraint(
            "mac_address GLOB '" + ":".join(["[0-9A-F][0-9A-F]"] * 6) + "'",
            name="mac_format",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True)
    current_ip: Mapped[str | None] = mapped_column(String(45))
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(255))
    is_trusted: Mapped[bool] = mapped_column(
        Boolean(create_constraint=True, name="trusted_boolean"), default=False, server_default=text("0")
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)

    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="source_device", passive_deletes=True
    )

    @validates("mac_address")
    def normalize_address(self, _key, value):
        return normalize_mac(value)
