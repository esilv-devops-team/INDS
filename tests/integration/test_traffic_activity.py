import json
from datetime import UTC, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Administrator, Device, MonitoringRun, TrafficSummary
from backend.ingest_traffic import ingest
from backend.services.traffic_activity import minute_start

CLIENT = "02:00:00:00:00:01"
PEER = "02:00:00:00:00:02"
UNKNOWN = "02:00:00:00:00:03"


def observation(seen_at, source, destination, size):
    return json.dumps({
        "timestamp": seen_at.replace(tzinfo=UTC).timestamp(),
        "source_mac": source,
        "destination_mac": destination,
        "captured_bytes": size,
    })


def create_run(engine, start):
    with Session(engine) as session, session.begin():
        admin_id = session.scalar(select(Administrator.id))
        run = MonitoringRun(started_at=start, started_by_id=admin_id)
        client = Device(mac_address=CLIENT, first_seen_at=start, last_seen_at=start)
        peer = Device(mac_address=PEER, first_seen_at=start, last_seen_at=start)
        session.add_all([run, client, peer])
        session.flush()
        return run.id, client.id, peer.id


def test_ingests_device_activity_and_exposes_rates(database, admin_api):
    engine, _, _ = database
    seen_at = minute_start(utc_now()) - timedelta(minutes=2)
    _, client_id, peer_id = create_run(engine, seen_at - timedelta(minutes=1))

    assert ingest(engine, [
        observation(seen_at, CLIENT, PEER, 150),
        observation(seen_at, UNKNOWN, CLIENT, 300),
        observation(seen_at, UNKNOWN, UNKNOWN, 500),
        observation(seen_at - timedelta(minutes=2), CLIENT, PEER, 900),
        "bad record",
    ]) == 0
    assert ingest(engine, [observation(seen_at + timedelta(seconds=1), CLIENT, UNKNOWN, 150)]) == 0
    with Session(engine) as session:
        summaries = {row.device_id: row for row in session.scalars(select(TrafficSummary))}
        assert set(summaries) == {client_id, peer_id}
        assert summaries[client_id].bytes_sent == 300
        assert summaries[client_id].packets_sent == 2
        assert summaries[client_id].bytes_received == 300
        assert summaries[peer_id].bytes_received == 150
        assert session.get(Device, client_id).last_seen_at == seen_at + timedelta(seconds=1)
        assert session.get(Device, peer_id).last_seen_at == seen_at - timedelta(minutes=1)

    response = admin_api.get(f"/api/devices/{client_id}/traffic")
    assert response.status_code == 200
    assert response.json()["upload_bps"] == 8
    assert response.json()["download_bps"] == 8
    assert admin_api.get("/api/devices/999999/traffic").status_code == 404
    assert admin_api.get("/api/statistics?window=1h").json()["totals"]["download"] == 450


def test_discards_batch_if_run_ends_during_capture(database, admin_api):
    engine, _, _ = database
    now = utc_now()
    assert ingest(engine, []) == 1
    run_id, _, _ = create_run(engine, now - timedelta(minutes=1))

    def capture():
        yield observation(now, CLIENT, PEER, 100)
        with Session(engine) as session, session.begin():
            run = session.get(MonitoringRun, run_id)
            run.ended_at = utc_now()
            run.stop_reason = "shutdown"

    assert ingest(engine, capture()) == 1
    with Session(engine) as session:
        assert session.scalar(select(TrafficSummary)) is None
