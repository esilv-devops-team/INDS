"""Exercise real migrated SQLite files, not a create_all substitute."""

from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
import shutil
import sqlite3
import os
import stat
import subprocess
import sys

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import delete, inspect, insert, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.database.config import PROJECT_ROOT, get_database_url
from backend.database import session as database_sessions
from backend.database.session import create_database_engine, get_session
from backend.database.models import Device, Incident


def finding(**overrides):
    values = dict(rule_code="port_scan", source_ip="192.168.50.66", target_ip="192.168.50.20")
    values.update(overrides)
    return Incident(**values)


def test_initialization_and_migration_match_models(database):
    engine, config, _ = database
    assert set(inspect(engine).get_table_names()) == {"devices", "incidents", "administrators", "monitoring_runs", "traffic_summaries", "ai_analyses", "response_actions", "audit_events", "alembic_version"}
    assert {i["name"] for i in inspect(engine).get_indexes("incidents")} == {
        "ix_incidents_status_created_at", "ix_incidents_source_device_id_created_at", "ix_incidents_monitoring_run_id"
    }
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0002"
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(text("PRAGMA journal_mode")) == "wal"
        assert connection.scalar(text("PRAGMA busy_timeout")) == 5000
    command.check(config)
    command.upgrade(config, "head")  # Repeat initialization is safe.


def test_records_survive_new_process_and_application_restart(database):
    engine, config, _ = database
    with Session(engine) as session:
        device = Device(mac_address="b8-27-eb-12-34-56", vendor="Raspberry Pi Foundation")
        incident = finding(source_device=device, evidence_json={"distinct_ports": 20})
        session.add(incident)
        session.commit()
        assert device.mac_address == "B8:27:EB:12:34:56"
        assert not device.is_trusted
        assert incident.status == "open"
        assert incident.risk_score is None and incident.severity is None
        assert device.incidents == [incident]
    command.upgrade(config, "head")  # Deployment restart must preserve records.
    engine.dispose()
    code = """
from backend.main import app
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from backend.database.session import get_engine
from backend.database.models import Device, Incident
with TestClient(app) as client:
    assert client.get('/health').status_code == 200
with Session(get_engine()) as session:
    device = session.scalar(select(Device))
    incident = session.scalar(select(Incident))
    assert device.mac_address == 'B8:27:EB:12:34:56'
    assert incident.source_device.id == device.id
    assert incident.evidence_json == {'distinct_ports': 20}
get_engine().dispose()
"""
    subprocess.run([sys.executable, "-c", code], cwd=PROJECT_ROOT, check=True)


@pytest.mark.parametrize("deletion", ["sql", "orm_loaded", "orm_unloaded"])
def test_foreign_keys_reject_orphans_and_preserve_history(database, deletion):
    engine, _, _ = database
    with Session(engine) as session:
        session.add(finding(source_device_id=999))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        device = Device(mac_address="00:11:22:33:44:55")
        session.add(finding(source_device=device))
        session.commit()
        if deletion == "sql":
            session.execute(delete(Device).where(Device.id == device.id))
        else:
            if deletion == "orm_loaded":
                assert len(device.incidents) == 1
            session.delete(device)
        session.commit()
        incident = session.scalar(select(Incident))
        assert incident.source_device_id is None
        assert incident.source_ip == "192.168.50.66"


@pytest.mark.parametrize("values", [
    {"risk_score": -1}, {"risk_score": 101}, {"severity": "Extreme"},
    {"status": "invalid"}, {"status": "resolved"},
])
def test_incident_constraints(database, values):
    engine, _, _ = database
    with Session(engine) as session:
        session.add(finding(**values))
        with pytest.raises(IntegrityError):
            session.commit()


def test_device_uniqueness_and_failed_transaction_rollback(database):
    engine, _, _ = database
    with Session(engine) as session:
        session.add_all([Device(mac_address="00:11:22:33:44:55"),
                         Device(mac_address="00-11-22-33-44-55")])
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        assert session.scalar(select(Device)) is None
        session.add(Device(mac_address="00:11:22:33:44:55"))
        session.commit()


@pytest.mark.parametrize("mac", ["invalid", "00:11:22:33:44:5G", "aa:bb:cc:dd:ee:ff"])
def test_mac_constraint_applies_to_direct_sql(database, mac):
    engine, _, _ = database
    with engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(insert(Device).values(mac_address=mac))


def test_chronological_constraints_and_resolved_incident(database):
    engine, _, _ = database
    now = datetime(2026, 1, 1)
    earlier = now - timedelta(seconds=1)
    with Session(engine) as session:
        session.add(Device(mac_address="00:11:22:33:44:55", first_seen_at=now, last_seen_at=earlier))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(finding(first_seen_at=now, last_seen_at=earlier))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(finding(created_at=now, updated_at=earlier))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        incident = finding(status="resolved", resolved_at=now, created_at=now,
                           updated_at=now, risk_score=100, severity="Critical")
        session.add(incident)
        session.commit()
        session.refresh(incident)
        assert incident.resolved_at == now


def test_startup_does_not_modify_existing_schema(database):
    engine, _, path = database
    # A pre-existing unrelated table must not be removed or recreated by startup.
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE local_marker (value TEXT NOT NULL)"))
        connection.execute(text("INSERT INTO local_marker VALUES ('preserved')"))
    engine.dispose()
    before = path.read_bytes()
    subprocess.run([sys.executable, "-c", "from backend.main import app; "
                    "from fastapi.testclient import TestClient; "
                    "client = TestClient(app); assert client.get('/health').status_code == 200"],
                   cwd=PROJECT_ROOT, check=True)
    assert path.read_bytes() == before
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT value FROM local_marker")) == "preserved"


def test_downgrade_and_reupgrade(database):
    engine, config, _ = database
    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    command.upgrade(config, "head")
    command.check(config)


def test_startup_does_not_create_database(tmp_path, monkeypatch):
    path = tmp_path / "untouched" / "inds.sqlite3"
    monkeypatch.setenv("INDS_DATABASE_URL", f"sqlite:///{path.as_posix()}")
    code = """
from backend.main import app
from fastapi.testclient import TestClient
with TestClient(app) as client:
    assert client.get('/health').status_code == 200
"""
    subprocess.run([sys.executable, "-c", code], cwd=PROJECT_ROOT, check=True)
    assert not path.parent.exists()


def test_session_dependency_rolls_back_uncommitted_work(database, monkeypatch):
    engine, _, _ = database
    monkeypatch.setattr(database_sessions, "get_engine", lambda: engine)
    dependency = get_session()
    try:
        session = next(dependency)
        session.add(Device(mac_address="00:11:22:33:44:55"))
        session.flush()
    finally:
        dependency.close()
    with Session(engine) as reader:
        assert reader.scalar(select(Device)) is None


def test_fresh_checkout_initializes_without_local_state(tmp_path, monkeypatch):
    checkout = tmp_path / "fresh checkout"
    shutil.copytree(PROJECT_ROOT / "backend", checkout / "backend",
                    ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.delenv("INDS_DATABASE_URL", raising=False)
    # Run outside the checkout as well: paths must follow alembic.ini, not cwd.
    for arguments in (("upgrade", "head"), ("current",), ("check",)):
        subprocess.run([sys.executable, "-m", "alembic", "-c",
                        str(checkout / "backend/database/alembic.ini"), *arguments], cwd=tmp_path, check=True)
    database_path = checkout / "data" / "inds.sqlite3"
    assert database_path.is_file()
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0002",)
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM administrators").fetchone() == (0,)


def test_offline_migration_sql(database, tmp_path, monkeypatch):
    engine, _, database_path = database
    monkeypatch.setenv("INDS_DATABASE_URL", f"sqlite:///{tmp_path.as_posix()}/offline.sqlite3")
    from io import StringIO
    output = StringIO()
    config = Config(str(PROJECT_ROOT / "backend/database/alembic.ini"), output_buffer=output)
    command.upgrade(config, "head", sql=True)
    assert "CREATE TABLE devices" in output.getvalue()
    assert "CREATE TABLE incidents" in output.getvalue()
    snapshot = PROJECT_ROOT / "backend/database/schema.sql"
    # Batch rebuilds may emit equivalent constraints/indexes in different orders.
    # Execute both scripts and compare their resulting schemas and revision.
    def schema_signature(connection):
        objects = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE sql IS NOT NULL ORDER BY type, name"
        ).fetchall()
        tables = [name for kind, name, _ in objects if kind == "table"]
        return (
            [(kind, name, sorted(line.strip().rstrip(",") for line in sql.splitlines()))
             for kind, name, sql in objects],
            {name: connection.execute(f'PRAGMA table_info("{name}")').fetchall() for name in tables},
            {name: sorted(connection.execute(f'PRAGMA foreign_key_list("{name}")').fetchall()) for name in tables},
            connection.execute("SELECT version_num FROM alembic_version").fetchone(),
        )

    engine.dispose()
    with closing(sqlite3.connect(database_path)) as migrated:
        expected = schema_signature(migrated)
        assert migrated.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert migrated.execute("PRAGMA foreign_key_check").fetchall() == []
    for script in (snapshot.read_text(encoding="utf-8-sig"), output.getvalue()):
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(script)
            assert schema_signature(connection) == expected
    assert not (tmp_path / "offline.sqlite3").exists()


def test_default_path_is_independent_of_working_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("INDS_DATABASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    assert Path(get_database_url().database) == PROJECT_ROOT / "data" / "inds.sqlite3"


@pytest.mark.parametrize("url", ["postgresql://localhost/inds", "sqlite://", "sqlite:///:memory:",
                                      "sqlite:///file.db?mode=ro", "sqlite://user:secret@localhost/file.db"])
def test_invalid_database_configuration(monkeypatch, url):
    monkeypatch.setenv("INDS_DATABASE_URL", url)
    with pytest.raises(ValueError):
        get_database_url()


@pytest.mark.skipif(os.name == "nt", reason="Windows permissions are managed through ACLs")
def test_new_data_directory_is_private(tmp_path, monkeypatch):
    path = tmp_path / "private-data" / "inds.sqlite3"
    monkeypatch.setenv("INDS_DATABASE_URL", f"sqlite:///{path.as_posix()}")
    engine = create_database_engine()
    try:
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    finally:
        engine.dispose()
