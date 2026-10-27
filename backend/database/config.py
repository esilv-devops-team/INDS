"""Database configuration shared by the backend and Alembic."""

import os
from pathlib import Path

from sqlalchemy.engine import URL, make_url

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def get_database_url() -> URL:
    """Resolve relative SQLite paths against the repository, never the cwd."""
    url = make_url(os.environ.get("INDS_DATABASE_URL", "sqlite:///data/inds.sqlite3"))
    if url.drivername not in ("sqlite", "sqlite+pysqlite"):
        raise ValueError("INDS_DATABASE_URL must use the SQLite sqlite3 driver")
    if (not url.database or url.database == ":memory:" or url.query
            or any(value is not None for value in (url.username, url.password, url.host, url.port))):
        raise ValueError("INDS_DATABASE_URL must identify a local SQLite file without query parameters")
    path = Path(url.database).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return url.set(database=str(path.resolve()))
