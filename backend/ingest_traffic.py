"""Read one finite batch of gateway traffic metadata from standard input."""

import sys

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.database.models import Device, MonitoringRun
from backend.database.session import get_engine
from backend.services.traffic_activity import persist_summaries, summarize_observations


def ingest(engine, lines):
    with Session(engine) as session:
        run = session.scalar(select(MonitoringRun).where(MonitoringRun.ended_at.is_(None)))
        if run is None:
            print("Traffic ingestion requires an active monitoring run.", file=sys.stderr)
            return 1
        run_id, started_at = run.id, run.started_at
        devices = dict(session.execute(select(Device.mac_address, Device.id)).tuples().all())

    windows, last_seen, skipped = summarize_observations(lines, devices, started_at)
    with Session(engine) as session, session.begin():
        if not persist_summaries(session, run_id, windows, last_seen):
            print("Monitoring ended during capture. Traffic batch discarded.", file=sys.stderr)
            return 1
    print(f"Saved {len(windows)} device windows. Skipped {skipped} invalid or out-of-run records.")
    return 0


def main():
    try:
        return ingest(get_engine(), sys.stdin)
    except (OSError, SQLAlchemyError) as error:
        print(f"Traffic ingestion failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
