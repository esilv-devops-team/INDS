import logging
from collections import deque
from threading import Event, Lock, Thread
from time import monotonic, time

logger = logging.getLogger(__name__)

MAX_PACKETS = 500
MAX_PER_POLL = 200
RATE_SECONDS = 60
IDLE_SECONDS = 120
WATCH_LIMIT_SECONDS = 600
CHUNK_SECONDS = 2
FLAG_NAMES = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}


def describe(metadata):
    if metadata.protocol == "ARP":
        if metadata.arp_operation == 1:
            return f"Who has {metadata.destination_ip}? Tell {metadata.source_ip}"
        if metadata.arp_operation == 2:
            return f"{metadata.source_ip} is at {(metadata.arp_sender_mac or metadata.source_mac).upper()}"
        return "ARP"
    if metadata.source_port is None:
        return metadata.protocol
    text = f"{metadata.source_port} → {metadata.destination_port}"
    if metadata.tcp_flags:
        text += " [" + ", ".join(FLAG_NAMES.get(flag, flag) for flag in metadata.tcp_flags) + "]"
    return text


class LiveFeed:
    def __init__(self):
        self.lock = Lock()
        self.clear()

    def clear(self):
        with self.lock:
            self.packets = deque(maxlen=MAX_PACKETS)
            self.counts = {}
            self.last_number = 0

    def add(self, metadata, mode):
        with self.lock:
            self.last_number += 1
            self.packets.append({
                "number": self.last_number,
                "time": metadata.timestamp,
                "mode": mode,
                "protocol": metadata.protocol,
                "source_mac": metadata.source_mac.upper(),
                "destination_mac": metadata.destination_mac.upper(),
                "source_ip": metadata.source_ip,
                "destination_ip": metadata.destination_ip,
                "source_port": metadata.source_port,
                "destination_port": metadata.destination_port,
                "tcp_flags": metadata.tcp_flags,
                "length": metadata.captured_bytes,
                "info": describe(metadata),
            })
            second = int(metadata.timestamp)
            self.counts[second] = self.counts.get(second, 0) + 1
            for old in [old for old in self.counts if old <= second - RATE_SECONDS]:
                del self.counts[old]

    def since(self, number):
        with self.lock:
            newer = [dict(packet) for packet in self.packets if packet["number"] > number]
            return newer[-MAX_PER_POLL:], self.last_number

    def rates(self, now=None):
        now = int(now or time())
        with self.lock:
            return [self.counts.get(second, 0) for second in range(now - RATE_SECONDS + 1, now + 1)]


class WatchCapture:
    def __init__(self):
        self.lock = Lock()
        self.stop_event = Event()
        self.thread = None
        self.started_at = 0
        self.last_seen = 0

    def running(self):
        return self.thread is not None and self.thread.is_alive() and not self.stop_event.is_set()

    def seconds_left(self):
        if not self.running():
            return None
        return max(int(WATCH_LIMIT_SECONDS - (monotonic() - self.started_at)), 0)

    def touch(self):
        self.last_seen = monotonic()

    def start(self, interface):
        from backend.services.monitoring import open_capture

        with self.lock:
            if self.running():
                self.touch()
                return
            capture_socket = open_capture(interface)
            self.stop_event.clear()
            self.started_at = self.last_seen = monotonic()
            self.thread = Thread(target=self.run, args=(interface, capture_socket), name="inds-live-watch", daemon=True)
            self.thread.start()

    def stop(self):
        with self.lock:
            self.stop_event.set()
            thread = self.thread
            self.thread = None
        if thread is not None:
            thread.join(timeout=CHUNK_SECONDS + 3)

    def run(self, interface, capture_socket):
        from gateway.traffic import capture_traffic

        try:
            while not self.stop_event.is_set():
                now = monotonic()
                if now - self.last_seen > IDLE_SECONDS or now - self.started_at > WATCH_LIMIT_SECONDS:
                    break
                capture_traffic([interface], lambda metadata: feed.add(metadata, "watch"),
                                duration=CHUNK_SECONDS, opened_socket={capture_socket: interface})
        except Exception:
            logger.exception("Watch-only capture failed on %s", interface)
        finally:
            capture_socket.close()
            self.stop_event.set()


feed = LiveFeed()
watch = WatchCapture()
