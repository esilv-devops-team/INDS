"""Database tests use isolated files initialized through the migration chain."""

from alembic import command
from alembic.config import Config
import pytest

from backend.database.config import PROJECT_ROOT
from backend.database.session import create_database_engine

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.database.session import get_session
from backend.main import app
from backend.services import auth


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

@pytest.fixture
def api(database):
    engine, _, _ = database

    def test_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    auth.failed_logins.clear()
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def admin_api(api):
    response = api.post("/api/auth/setup", json={"username": "admin", "password": "password123"})
    assert response.status_code == 201
    return api
