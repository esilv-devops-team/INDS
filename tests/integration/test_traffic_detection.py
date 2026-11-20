from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from backend.database.models import Administrator, Device, MonitoringRun, TrafficSummary
from backend.services.traffic_detection import TrafficDetection, load_traffic_settings


def test_detection_uses_closed_windows_for_the_selected_run(database, monkeypatch):
    engine, _, _ = database
    monkeypatch.setenv("INDS_TRAFFIC_SPIKE_WINDOW_MINUTES", "2")
    monkeypatch.setenv("INDS_TRAFFIC_SPIKE_BYTES_PER_MINUTE", "100")
    start = datetime(2026, 11, 20, 10)
    minute = timedelta(minutes=1)
    with Session(engine) as session, session.begin():
        admin = Administrator(username="admin", password_hash="test")
        device = Device(mac_address="02:00:00:00:46:01")
        previous = MonitoringRun(
            started_by=admin, started_at=start - minute, ended_at=start, stop_reason="shutdown",
        )
        run = MonitoringRun(started_by=admin, started_at=start + timedelta(seconds=5))
        session.add_all([previous, run, device])
        session.flush()
        run_id, device_id = run.id, device.id
        for run_owner, offset, size in ((run, 0, 1000), (run, 2, 110), (run, 3, 95), (previous, 2, 900)):
            bucket = start + offset * minute
            session.add(TrafficSummary(
                device=device, monitoring_run=run_owner, window_start=bucket,
                window_end=bucket + minute, bytes_received=size,
            ))

    detector = TrafficDetection(load_traffic_settings(), start + timedelta(seconds=5))
    with Session(engine) as session:
        assert detector.evaluate_ready(session, run_id, start + 3 * minute) == []
        finding, = detector.evaluate_ready(session, run_id, start + 4 * minute)
        assert finding.source_device_id == device_id
        assert finding.measured["bytes_received"] == 205
        assert detector.evaluate_ready(session, run_id, start + 4 * minute) == []
