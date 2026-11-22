from datetime import UTC, datetime
from types import SimpleNamespace

from scapy.all import IP, TCP, UDP, Ether

from backend.services.port_scan_detection import evaluate_port_scan
from detection.registry import port_scan_rules
from detection.rules.port_scan import PortScanSettings
from gateway.traffic import read_metadata

ATTACKER_MAC = "02:00:00:00:00:66"
START = datetime(2026, 11, 22, 10)
DEVICES = {"02:00:00:00:00:66": 7}


def packet(layer, seconds=1, mac=ATTACKER_MAC):
    frame = Ether(bytes(Ether(src=mac, dst="02:00:00:00:00:01") / IP(src="192.168.50.66", dst="192.168.50.20") / layer))
    frame.sniffed_on = "ap0"
    frame.time = START.replace(tzinfo=UTC).timestamp() + seconds
    return read_metadata(frame)


def scan(engine, layers, devices=DEVICES):
    findings = []
    for layer in layers:
        findings += evaluate_port_scan(engine, packet(layer), devices, START)
    return findings


def test_capture_keeps_tcp_flags():
    assert packet(TCP(dport=22, flags="S")).tcp_flags == "S"
    assert packet(TCP(dport=22, flags="SA")).tcp_flags == "SA"
    assert packet(UDP(dport=53)).tcp_flags is None


def test_syn_scan_is_detected_with_device_id():
    engine = port_scan_rules(PortScanSettings(distinct_ports=5))
    finding, = scan(engine, [TCP(dport=port, flags="S") for port in range(20, 25)])
    assert finding.source_device_id == 7
    assert finding.source_mac == "02:00:00:00:00:66"
    assert finding.evidence["protocol"] == "TCP"


def test_replies_and_open_connections_are_not_counted():
    engine = port_scan_rules(PortScanSettings(distinct_ports=5))
    layers = [TCP(dport=port, flags="SA") for port in range(40000, 40010)]
    layers += [TCP(dport=port, flags="A") for port in range(41000, 41010)]
    assert scan(engine, layers) == []


def test_udp_counts_only_for_known_devices():
    engine = port_scan_rules(PortScanSettings(distinct_ports=5))
    assert scan(engine, [UDP(dport=port) for port in range(50000, 50010)], devices={}) == []
    finding, = scan(engine, [UDP(dport=port) for port in range(100, 105)])
    assert finding.evidence["protocol"] == "UDP"


def test_other_packets_are_ignored():
    engine = port_scan_rules(PortScanSettings(distinct_ports=2))
    early = packet(TCP(dport=22, flags="S"), seconds=-5)
    broken = SimpleNamespace(protocol="TCP", destination_port=22, tcp_flags="S", timestamp=1.0, source_mac="nope")
    for metadata in (SimpleNamespace(protocol="ARP"), SimpleNamespace(protocol="ICMP"), early, broken):
        assert evaluate_port_scan(engine, metadata, DEVICES, START) == []
    disabled = port_scan_rules(PortScanSettings(enabled=False))
    assert evaluate_port_scan(disabled, packet(TCP(dport=22, flags="S")), DEVICES, START) == []