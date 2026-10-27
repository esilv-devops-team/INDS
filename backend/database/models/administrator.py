"""Local administrator identities; authentication is implemented separately."""

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, validates

from backend.database.base import Base, utc_now


class Administrator(Base):
    __tablename__ = "administrators"
    __table_args__ = (
        CheckConstraint("username = lower(trim(username)) AND length(username) > 0", name="username_format"),
        CheckConstraint("length(password_hash) > 0", name="password_hash_present"),
        CheckConstraint("last_login_at IS NULL OR last_login_at >= created_at", name="login_order"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(
        Boolean(create_constraint=True, name="active_boolean"), default=True, server_default=text("1")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)

    @validates("username")
    def normalize_username(self, _key, value):
        return value.strip().lower()
