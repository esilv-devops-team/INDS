"""Database tests use isolated files initialized through the migration chain."""

from alembic import command
from alembic.config import Config
import pytest

from backend.database.config import PROJECT_ROOT
from backend.database.session import create_database_engine


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "test.sqlite3"
    monkeypatch.setenv("INDS_DATABASE_URL", f"sqlite:///{path.as_posix()}")
    config = Config(str(PROJECT_ROOT / "backend/database/alembic.ini"))
    command.upgrade(config, "head")
    engine = create_database_engine()
    try:
        yield engine, config, path
    finally:
        engine.dispose()
