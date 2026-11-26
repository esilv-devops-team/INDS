import time
from unittest.mock import Mock

import pytest

from backend.services import live_traffic, monitoring
from backend.services.live_traffic import LiveFeed, WatchCapture, describe
from gateway import traffic
from gateway.traffic import TrafficMetadata


def packet(protocol="TCP", flags="S", source_port=51000, destination_port=22, when=None, **extra):
    values = {
        "interface": "eth1", "timestamp": when or time.time(), "protocol": protocol,
        "ip_protocol": {"TCP": 6, "UDP": 17, "ICMP": 1}.get(protocol), "source_mac": "02:00:00:00:00:66",
        "destination_mac": "02:00:00:00:00:01", "source_ip": "192.168.50.66", "destination_ip": "192.168.50.1",
        "source_port": source_port, "destination_port": destination_port, "captured_bytes": 60,
        "tcp_flags": flags if protocol == "TCP" else None,
    }
    values.update(extra)
    return TrafficMetadata(**values)


@pytest.mark.parametrize("metadata, text", [
    (packet(), "51000 → 22 [SYN]"),
    (packet(flags="SA", source_port=22, destination_port=51000), "22 → 51000 [SYN, ACK]"),
    (packet(flags="PA"), "51000 → 22 [PSH, ACK]"),
    (packet(protocol="UDP", source_port=5353, destination_port=53), "5353 → 53"),
    (packet(protocol="ICMP", source_port=None, destination_port=None), "ICMP"),
    (packet(protocol="ARP", source_port=None, destination_port=None, arp_operation=1), "Who has 192.168.50.1? Tell 192.168.50.66"),
    (packet(protocol="ARP", source_port=None, destination_port=None, arp_operation=2, arp_sender_mac="02:00:00:00:00:aa"),
     "192.168.50.66 is at 02:00:00:00:00:AA"),
    (packet(protocol="ARP", source_port=None, destination_port=None, arp_operation=3), "ARP"),
])
def test_describe(metadata, text):
    assert describe(metadata) == text


def test_feed_keeps_the_last_packets():
    feed = LiveFeed()
    for _ in range(live_traffic.MAX_PACKETS + 20):
        feed.add(packet(source_mac="02:00:00:00:00:6a"), "watch")

    newest, last = feed.since(0)
    assert last == live_traffic.MAX_PACKETS + 20
    assert len(newest) == live_traffic.MAX_PER_POLL
    assert newest[-1]["number"] == last
    assert newest[-1]["source_mac"] == "02:00:00:00:00:6A"
    assert newest[-1]["info"] == "51000 → 22 [SYN]"
    assert newest[-1]["mode"] == "watch"
    assert feed.since(last) == ([], last)
    assert [item["number"] for item in feed.since(last - 2)[0]] == [last - 1, last]

    feed.clear()
    assert feed.since(0) == ([], 0)


def test_packets_per_second():
    feed = LiveFeed()
    now = 1_000_000
    feed.add(packet(when=now - 100), "protect")
    for _ in range(3):
        feed.add(packet(when=now - 0.5), "protect")
    feed.add(packet(when=now + 0.2), "protect")
    rates = feed.rates(now)
    assert len(rates) == live_traffic.RATE_SECONDS
    assert (rates[-1], rates[-2], sum(rates)) == (1, 3, 4)
    assert now - 100 not in feed.counts


@pytest.fixture
def capture(monkeypatch):
    feed = LiveFeed()
    sockets = []

    def opened(interface):
        sockets.append(Mock())
        return sockets[-1]

    def fake_capture(interfaces, on_metadata, duration, opened_socket):
        on_metadata(packet())
        time.sleep(0.01)

    monkeypatch.setattr(live_traffic, "feed", feed)
    monkeypatch.setattr(monitoring, "open_capture", opened)
    monkeypatch.setattr(traffic, "capture_traffic", fake_capture)
    return feed, sockets


def wait_until(check):
    for _ in range(200):
        if check():
            return True
        time.sleep(0.01)
    return False


def test_watch_capture_runs_until_stopped(capture):
    feed, sockets = capture
    watch = WatchCapture()
    assert watch.seconds_left() is None
    watch.start("eth1")
    watch.start("eth1")
    assert len(sockets) == 1
    assert watch.running()
    assert wait_until(lambda: feed.since(0)[1] >= 3)
    assert 0 < watch.seconds_left() <= live_traffic.WATCH_LIMIT_SECONDS
    watch.stop()
    assert not watch.running()
    sockets[0].close.assert_called_once_with()
    assert {item["mode"] for item in feed.since(0)[0]} == {"watch"}


@pytest.mark.parametrize("setting", ["IDLE_SECONDS", "WATCH_LIMIT_SECONDS"])
def test_watch_capture_stops_by_itself(capture, monkeypatch, setting):
    _, sockets = capture
    monkeypatch.setattr(live_traffic, setting, 0.05)
    watch = WatchCapture()
    watch.start("eth1")
    assert wait_until(lambda: not watch.running())
    sockets[0].close.assert_called_once_with()


def test_watch_capture_survives_capture_errors(capture, monkeypatch):
    _, sockets = capture
    monkeypatch.setattr(traffic, "capture_traffic", Mock(side_effect=OSError("capture ended unexpectedly")))
    watch = WatchCapture()
    watch.start("eth1")
    assert wait_until(lambda: not watch.running())
    sockets[0].close.assert_called_once_with()
