from unittest.mock import Mock

import pytest
from scapy.all import ARP, Dot1Q, Ether, IP, IPv6, Raw, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrFragment, IPv6ExtHdrHopByHop

from gateway import traffic


def captured(payload):
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / payload
    packet = Ether(bytes(frame))
    packet.sniffed_on = "ap0"
    packet.time = 123.5
    return packet


@pytest.mark.parametrize(
    ("payload", "protocol", "source", "destination", "ports"),
    [
        (Dot1Q(vlan=10) / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1234, dport=443),
         "TCP", "192.0.2.1", "192.0.2.2", (1234, 443)),
        (IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / UDP(sport=1234, dport=53),
         "UDP", "2001:db8::1", "2001:db8::2", (1234, 53)),
        (ARP(psrc="192.0.2.1", pdst="192.0.2.2", hwsrc="02:00:00:00:00:01"),
         "ARP", "192.0.2.1", "192.0.2.2", (None, None)),
        (IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(nh=17, offset=1) / Raw(b"fragment"),
         "UDP", "2001:db8::1", "2001:db8::2", (None, None)),
    ],
)
def test_reads_outer_metadata(payload, protocol, source, destination, ports):
    packet = captured(payload)
    metadata = traffic.read_metadata(packet)
    assert metadata.interface == "ap0"
    assert metadata.timestamp == 123.5
    assert metadata.protocol == protocol
    assert (metadata.source_ip, metadata.destination_ip) == (source, destination)
    assert (metadata.source_port, metadata.destination_port) == ports
    assert metadata.source_mac == "02:00:00:00:00:01"
    assert metadata.destination_mac == "02:00:00:00:00:02"
    assert metadata.captured_bytes == len(packet.original)


def test_capture_skips_malformed_frames_and_keeps_reading(monkeypatch):
    receive = Mock()

    def sniff(*, iface, filter, prn, store, chainCC):
        assert iface == ["ap0"]
        assert filter == "ip"
        assert not store
        assert chainCC
        prn(captured(IP(proto=6) / Raw(b"short")))
        prn(captured(IP() / UDP()))

    monkeypatch.setattr(traffic, "sniff", sniff)
    traffic.capture_traffic(["ap0", "ap0"], receive, capture_filter="ip")
    receive.assert_called_once()
    assert receive.call_args.args[0].protocol == "UDP"


def test_cli_reports_capture_failure(monkeypatch, capsys):
    monkeypatch.setattr(traffic.sys, "argv", ["traffic", "--iface", "ap0"])
    monkeypatch.setattr(traffic, "sniff", Mock(side_effect=OSError("permission denied")))
    assert traffic.main() == 1
    assert "ap0: permission denied" in capsys.readouterr().err
