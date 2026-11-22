from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, JSON, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base, utc_now


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name="severity_values"),
        CheckConstraint("cooldown_seconds > 0", name="cooldown_positive"),
        CheckConstraint("json_valid(settings_json) AND json_type(settings_json) = 'object'", name="settings_object"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_code: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean(create_constraint=True, name="enabled_boolean"), default=True, server_default=text("1")
    )
    severity: Mapped[str] = mapped_column(String(10))
    cooldown_seconds: Mapped[int]
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, onupdate=utc_now)