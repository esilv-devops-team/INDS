"""Own the lifetime of the traffic collector for one gateway API process."""

import logging
import os
from dataclasses import asdict
from datetime import timedelta
import json
from threading import Event, Lock, Thread

from sqlalchemy import case, select, update
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device, MonitoringRun, ResponseAction
from backend.services.arp_detection import evaluate_arp, load_arp_bindings
from backend.services.audit import record_event
from backend.services.device_inventory import save_observation
from backend.services.response_execution import ResponseError, reconcile_blocks
from backend.services.traffic_activity import TrafficAccumulator, persist_summaries
from backend.services.traffic_detection import TrafficDetection, load_traffic_settings
from detection.registry import arp_rules

logger = logging.getLogger(__name__)
CAPTURE_SECONDS = 2


class MonitoringError(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status


def configured_interface():
    return os.environ.get("INDS_MONITOR_INTERFACE", "").strip()


def open_capture(interface):
    from scapy.all import conf

    return conf.L2listen(iface=interface)


def capture_batch(interface, capture_socket, receive, discoveries):
    from gateway.discovery import add_device, read_packet
    from gateway.traffic import capture_traffic

    def observe_device(packet):
        try:
            add_device(discoveries, read_packet(packet))
        except (AttributeError, IndexError, TypeError, ValueError):
            logger.debug("Skipping malformed discovery packet on %s", interface)

    capture_traffic([interface], receive, duration=CAPTURE_SECONDS,
                    opened_socket={capture_socket: interface}, on_packet=observe_device)


def guest_observations(interface, discoveries):
    from gateway.discovery import macs_on_port

    guests = macs_on_port(interface)
    ignored = os.environ.get("INDS_MONITOR_AP_MAC", "").strip().upper()
    return [device for mac, device in discoveries.items() if mac in guests and mac != ignored]

def cancel_pending_actions(session, admin=None):
    pending = session.scalars(select(ResponseAction).where(ResponseAction.approval_status == "pending")).all()
    for action in pending:
        action.approval_status = "cancelled"
        action.decided_by_id = admin.id if admin else None
        action.decided_at = utc_now()
        record_event(
            session, "response_action.cancelled", admin=admin,
            response_action_id=action.id, incident_id=action.incident_id, device_id=action.device_id,
            details={"reason": "monitoring stopped"},
        )

def close_run(engine, reason, *, run_id=None, admin=None):
    now = utc_now()
    command = update(MonitoringRun).where(MonitoringRun.ended_at.is_(None))
    if run_id is not None:
        command = command.where(MonitoringRun.id == run_id)
    with Session(engine) as session, session.begin():
        closed_id = session.execute(command.values(
            ended_at=case((MonitoringRun.started_at > now, MonitoringRun.started_at), else_=now),
            stop_reason=reason,
            stopped_by_id=admin.id if admin else None,
        ).returning(MonitoringRun.id)).scalar_one_or_none()
        if closed_id is not None:
            record_event(session, "monitoring.stop", admin=admin, monitoring_run_id=closed_id,
                         outcome="failure" if reason == "failure" else "success",
                         details={"reason": reason})
            cancel_pending_actions(session, admin)
        


class MonitoringController:
    def __init__(self):
        self.lock = Lock()
        self.stop_event = Event()
        self.worker = None
        self.engine = None
        self.firewall_cleanup_needed = False

    def cleanup_firewall(self, engine, admin=None):
        try:
            reconcile_blocks(engine, admin)
        except ResponseError as error:
            self.firewall_cleanup_needed = True
            raise MonitoringError(error.status, str(error)) from error
        self.firewall_cleanup_needed = False

    def start(self, engine, admin):
        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                if self.stop_event.is_set():
                    raise MonitoringError(409, "The previous collector is still stopping.")
                return
            interface = configured_interface()
            if not interface:
                raise MonitoringError(503, "Set INDS_MONITOR_INTERFACE to the AP-facing port.")
            try:
                detection_settings = load_traffic_settings()
                arp_bindings = load_arp_bindings()
            except ValueError as error:
                raise MonitoringError(503, f"Invalid detection settings: {error}") from error
            with Session(engine) as session:
                if session.scalar(select(MonitoringRun.id).where(MonitoringRun.ended_at.is_(None))):
                    raise MonitoringError(409, "Stop the unfinished monitoring run before starting again.")
            self.cleanup_firewall(engine)

            try:
                capture_socket = open_capture(interface)
            except Exception as error:
                logger.exception("Unable to open capture on %s", interface)
                raise MonitoringError(503, f"Unable to open traffic capture on {interface}.") from error

            run_id = None
            try:
                with Session(engine) as session, session.begin():
                    run = MonitoringRun(started_by_id=admin.id)
                    session.add(run)
                    session.flush()
                    record_event(session, "monitoring.start", admin=admin, monitoring_run_id=run.id)
                    run_id, started_at = run.id, run.started_at
                self.stop_event.clear()
                self.worker = Thread(
                    target=self.collect,
                    args=(engine, interface, capture_socket, run_id, started_at, detection_settings, arp_bindings),
                    name="inds-traffic", daemon=True,
                )
                self.worker.start()
                self.engine = engine
            except Exception:
                capture_socket.close()
                if run_id is not None:
                    close_run(engine, "failure", run_id=run_id)
                raise

    def stop(self, engine, *, admin=None):
        with self.lock:
            self.stop_event.set()
            close_run(engine, "administrator" if admin else "shutdown", admin=admin)
            worker = self.worker
            self.cleanup_firewall(engine, admin)
        if worker is not None and worker.is_alive():
            worker.join(timeout=CAPTURE_SECONDS + 5)
            if worker.is_alive():
                raise MonitoringError(503, "Timed out waiting for traffic capture to stop.")

    def shutdown(self):
        if self.engine is not None:
            self.stop(self.engine)
            self.engine = None

    def log_findings(self, findings):
        for finding in findings:
            if self.stop_event.is_set():
                return
            payload = asdict(finding)
            payload["timestamp"] = finding.timestamp.isoformat()
            logger.warning("Detection finding: %s", json.dumps(payload))

    def collect(self, engine, interface, capture_socket, run_id, started_at, detection_settings, arp_bindings):
        detection = TrafficDetection(detection_settings, started_at)
        arp_engine = arp_rules(arp_bindings)
        try:
            while not self.stop_event.is_set():
                with Session(engine) as session:
                    devices = dict(session.execute(select(Device.mac_address, Device.id)).tuples().all())
                batch = TrafficAccumulator(devices, started_at)
                discoveries = {}
                arp_findings = []

                def receive(metadata):
                    batch.add(metadata)
                    arp_findings.extend(evaluate_arp(arp_engine, metadata, devices, started_at))

                capture_batch(interface, capture_socket, receive, discoveries)
                if self.stop_event.is_set():
                    break
                guests = guest_observations(interface, discoveries) if discoveries else []
                if batch.windows or guests:
                    with Session(engine) as session, session.begin():
                        if not persist_summaries(session, run_id, batch.windows, batch.last_seen):
                            break
                        for guest in guests:
                            save_observation(session, **guest)
                try:
                    self.log_findings(arp_findings)
                    with Session(engine) as session:
                        settled = utc_now() - timedelta(seconds=CAPTURE_SECONDS)
                        findings = detection.evaluate_ready(session, run_id, settled)
                    self.log_findings(findings)
                except Exception:
                    logger.exception("Traffic detection failed for monitoring run %s", run_id)
        except Exception:
            logger.exception("Traffic collector failed on %s", interface)
            with self.lock:
                if not self.stop_event.is_set():
                    close_run(engine, "failure", run_id=run_id)
                    try:
                        self.cleanup_firewall(engine)
                    except MonitoringError:
                        logger.error("Firewall cleanup after capture failure needs operator attention.")
        finally:
            capture_socket.close()
