"""Own the lifetime of the traffic collector for one gateway API process."""

import logging
import os
import subprocess
from dataclasses import asdict
from datetime import timedelta
from ipaddress import IPv4Interface
import json
from threading import Event, Lock, Thread

from sqlalchemy import case, select, update
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Administrator, Device, MonitoringPreference, MonitoringRun, ResponseAction
from backend.services.arp_detection import evaluate_arp
from backend.services.audit import record_event
from backend.services.detection_rules import arp_spoofing_settings, port_scan_settings, traffic_spike_settings
from backend.services.device_inventory import expire_addresses, save_observation
from backend.services.incident_creation import record_findings
from backend.services.live_traffic import feed as live_feed
from backend.services.live_traffic import watch as live_watch
from backend.services.port_scan_detection import evaluate_port_scan
from backend.services.response_execution import ResponseError, expire_blocks, reconcile_blocks
from backend.services.traffic_activity import TrafficAccumulator, persist_summaries
from backend.services.traffic_detection import TrafficDetection
from detection.registry import arp_rules, port_scan_rules

logger = logging.getLogger(__name__)
CAPTURE_SECONDS = 2


class MonitoringError(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status


def configured_interface():
    return os.environ.get("INDS_MONITOR_INTERFACE", "").strip()


def routed_lan(interface):
    address = os.environ.get("INDS_LAN_ADDRESS", "192.168.50.1/24" if interface == "eth1" else "")
    return IPv4Interface(address) if address else None


def open_capture(interface):
    from scapy.all import conf

    return conf.L2listen(iface=interface)


def capture_batch(interface, capture_socket, receive, discoveries):
    from gateway.discovery import add_device, read_packet
    from gateway.traffic import capture_traffic

    provenance = routed_lan(interface) is not None

    def observe_device(packet):
        try:
            add_device(discoveries, read_packet(packet, provenance=provenance))
        except (AttributeError, IndexError, TypeError, ValueError):
            logger.debug("Skipping malformed discovery packet on %s", interface)

    capture_traffic([interface], receive, duration=CAPTURE_SECONDS,
                    opened_socket={capture_socket: interface}, on_packet=observe_device)


def guest_observations(interface, discoveries):
    from gateway.discovery import macs_on_port

    guests = macs_on_port(interface)
    ignored = os.environ.get("INDS_MONITOR_AP_MAC", "").strip().upper()
    return [device for mac, device in discoveries.items() if mac in guests and mac != ignored]


def routed_observations(interface, lan, discoveries, now, *, snapshot):
    from gateway.discovery import is_real_mac, lan_client_ip, read_leases, read_neighbors
    from backend.services.vendor_lookup import normalize_mac

    observations = list(discoveries.values())
    if snapshot:
        sources = (
            (read_neighbors, (interface,)),
            (read_leases, (os.environ.get("INDS_DHCP_LEASE_FILE", "/var/lib/misc/dnsmasq.leases"), now)),
        )
        for read, args in sources:
            try:
                observations.extend(read(*args))
            except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as error:
                logger.warning("Routed discovery source %s unavailable: %s", read.__name__, error)
    ignored = os.environ.get("INDS_MONITOR_AP_MAC", "").strip().upper()
    seen = set()
    for item in observations:
        try:
            mac = normalize_mac(item["mac"])
        except ValueError:
            continue
        if mac == ignored or not is_real_mac(mac):
            continue
        source = item["source"]
        ip = lan_client_ip(item["ip"], lan)
        if source != "dhcp_request" and not ip:
            continue
        key = (mac, source, ip)
        if key in seen:
            continue
        seen.add(key)
        expiration = item.get("expires_at") if source == "dhcp_lease" else now + timedelta(minutes=2)
        yield dict(mac=mac, ip=None if source == "dhcp_request" else ip,
                   hostname=item["hostname"], source=source, expires_at=expiration)


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
        if reason == "administrator":
            session.merge(MonitoringPreference(id=1, enabled_by_id=None))
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
        self.recovery_error = None
        self.detection_degraded = False

    def recover(self, engine, *, preferences_available=True):
        close_run(engine, "interrupted")
        try:
            self.cleanup_firewall(engine)
            if not preferences_available:
                return
            with Session(engine) as session:
                preference = session.get(MonitoringPreference, 1)
                if not preference or not preference.enabled_by_id:
                    return
                admin = session.get(Administrator, preference.enabled_by_id)
                if admin:
                    self.start(engine, admin, recovering=True)
        except MonitoringError as error:
            self.recovery_error = str(error)
            with Session(engine) as session, session.begin():
                record_event(session, "monitoring.recovery_failed", outcome="failure",
                             details={"reason": str(error)})
            logger.warning("Monitoring startup recovery failed: %s", error)

    def cleanup_firewall(self, engine, admin=None):
        try:
            reconcile_blocks(engine, admin)
        except ResponseError as error:
            self.firewall_cleanup_needed = True
            raise MonitoringError(error.status, str(error)) from error
        self.firewall_cleanup_needed = False

    def start(self, engine, admin, *, recovering=False):
        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                if self.stop_event.is_set():
                    raise MonitoringError(409, "The previous collector is still stopping.")
                return
            interface = configured_interface()
            if not interface:
                raise MonitoringError(503, "Set INDS_MONITOR_INTERFACE to the AP-facing port.")
            live_watch.stop()
            with Session(engine) as session:
                try:
                    detection_settings = traffic_spike_settings(session)
                    arp_settings = arp_spoofing_settings(session)
                    scan_settings = port_scan_settings(session)
                except ValueError as error:
                    raise MonitoringError(503, f"Invalid detection settings: {error}") from error
                if session.scalar(select(MonitoringRun.id).where(MonitoringRun.ended_at.is_(None))):
                    raise MonitoringError(409, "Stop the unfinished monitoring run before starting again.")
            if not recovering:
                self.cleanup_firewall(engine)

            try:
                routed_lan(interface)
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
                    session.merge(MonitoringPreference(id=1, enabled_by_id=admin.id))
                    record_event(session, "monitoring.start", admin=None if recovering else admin,
                                 monitoring_run_id=run.id, details={"recovered": True} if recovering else None)
                    run_id, started_at = run.id, run.started_at
                self.stop_event.clear()
                self.worker = Thread(
                    target=self.collect,
                    args=(engine, interface, capture_socket, run_id, started_at, detection_settings, arp_settings, scan_settings),
                    name="inds-traffic", daemon=True,
                )
                self.worker.start()
                self.engine = engine
                self.recovery_error = None
            except Exception:
                capture_socket.close()
                if run_id is not None:
                    close_run(engine, "failure", run_id=run_id)
                raise

    def stop(self, engine, *, admin=None):
        with self.lock:
            self.stop_event.set()
            close_run(engine, "administrator" if admin else "shutdown", admin=admin)
            if admin:
                self.recovery_error = None
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

    def report_findings(self, engine, run_id, findings):
        if not findings or self.stop_event.is_set():
            return
        self.log_findings(findings)
        with Session(engine) as session, session.begin():
            record_findings(session, run_id, findings)

    def collect(self, engine, interface, capture_socket, run_id, started_at, detection_settings, arp_settings, scan_settings):
        detection = TrafficDetection(detection_settings, started_at)
        arp_engine = arp_rules(**arp_settings)
        scan_engine = port_scan_rules(scan_settings)
        try:
            lan = routed_lan(interface)
            next_snapshot = started_at
            next_expiry_check = started_at
            while not self.stop_event.is_set():
                with Session(engine) as session:
                    devices = dict(session.execute(select(Device.mac_address, Device.id)).tuples().all())
                batch = TrafficAccumulator(devices, started_at)
                discoveries = {}
                packet_findings = []
                packets = []

                def receive(metadata):
                    batch.add(metadata)
                    packet_findings.extend(evaluate_arp(arp_engine, metadata, devices, started_at))
                    packet_findings.extend(evaluate_port_scan(scan_engine, metadata, devices, started_at))

                store = packets.append if lan else receive

                def handle(metadata):
                    store(metadata)
                    try:
                        live_feed.add(metadata, "protect")
                    except (AttributeError, TypeError, ValueError):
                        logger.debug("Skipping a packet for the live view")

                capture_batch(interface, capture_socket, handle, discoveries)
                if self.stop_event.is_set():
                    break
                if lan:
                    now = utc_now()
                    if now >= next_expiry_check and self.lock.acquire(blocking=False):
                        try:
                            if not self.stop_event.is_set():
                                expire_blocks(engine)
                        finally:
                            self.lock.release()
                        next_expiry_check = now + timedelta(seconds=5)
                    snapshot = now >= next_snapshot
                    guests = list(routed_observations(interface, lan, discoveries, now, snapshot=snapshot))
                    if snapshot:
                        next_snapshot = now + timedelta(seconds=15)
                else:
                    guests = guest_observations(interface, discoveries) if discoveries else []
                if lan or batch.windows or guests:
                    with Session(engine) as session, session.begin():
                        if not persist_summaries(session, run_id, batch.windows, batch.last_seen):
                            break
                        if lan:
                            expire_addresses(session, now)
                        for guest in guests:
                            save_observation(session, **guest)
                        if lan and packets:
                            session.flush()
                            devices.update(session.execute(select(Device.mac_address, Device.id)).tuples().all())
                            for packet in packets:
                                receive(packet)
                            persist_summaries(session, run_id, batch.windows, batch.last_seen)
                try:
                    self.report_findings(engine, run_id, packet_findings)
                    with Session(engine) as session:
                        settled = utc_now() - timedelta(seconds=CAPTURE_SECONDS)
                        findings = detection.evaluate_ready(session, run_id, settled)
                    self.report_findings(engine, run_id, findings)
                    self.detection_degraded = False
                except Exception:
                    self.detection_degraded = True
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
