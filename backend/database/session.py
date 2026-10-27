"""Lazy connections; schema changes are exclusively managed by Alembic."""

from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from backend.database.config import get_database_url


def create_database_engine() -> Engine:
    url = get_database_url()
    Path(url.database).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine = create_engine(
        url, connect_args={"check_same_thread": False, "timeout": 5}, hide_parameters=True
    )

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, _record):
        # Explicit BEGIN also makes SQLite DDL and savepoints transactional.
        connection.isolation_level = None
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
        finally:
            cursor.close()

    @event.listens_for(engine, "begin")
    def begin_transaction(connection):
        connection.exec_driver_sql("BEGIN")

    return engine


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """One lazy engine per process; configure the environment before first use."""
    return create_database_engine()


def get_session():
    """FastAPI dependency: callers explicitly commit; failures roll back on close."""
    with Session(get_engine()) as session:
        yield session
