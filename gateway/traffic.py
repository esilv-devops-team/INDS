"""Passively collect packet metadata on explicitly selected gateway ports."""

import argparse
from dataclasses import asdict, dataclass
import json
import logging
import sys
from time import monotonic

from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP, Dot1Q, sniff
from scapy.error import Scapy_Exception
from scapy.layers.inet6 import IPv6ExtHdrFragment, _IPv6ExtHdr

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrafficMetadata:
    interface: str
    timestamp: float
    protocol: str
    ip_protocol: int | None
    source_mac: str
    destination_mac: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    captured_bytes: int


def read_metadata(packet):
    ethernet = packet.getlayer(Ether)
    if ethernet is None:
        return None

    network = ethernet.payload
    while isinstance(network, Dot1Q):
        network = network.payload

    transport = network.payload
    fragmented = False
    if isinstance(network, IP):
        if network.ihl < 5 or network.len < network.ihl * 4:
            raise ValueError("invalid IPv4 header length")
        ip_protocol = network.proto
        fragmented = network.frag != 0
    elif isinstance(network, IPv6):
        ip_protocol = network.nh
        while isinstance(transport, _IPv6ExtHdr):
            ip_protocol = transport.nh
            if isinstance(transport, IPv6ExtHdrFragment) and transport.offset:
                fragmented = True
                break
            transport = transport.payload
    elif isinstance(network, ARP) and network.hwtype == 1 and network.ptype == 0x0800:
        ip_protocol = None
    else:
        return None

    if ip_protocol is None:
        protocol = "ARP"
        source_ip, destination_ip = network.psrc, network.pdst
    else:
        protocol = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(ip_protocol, "IP")
        source_ip, destination_ip = network.src, network.dst

    source_port = destination_port = None
    port_header = {6: TCP, 17: UDP}.get(ip_protocol)
    if not fragmented and port_header is not None:
        if not isinstance(transport, port_header):
            raise ValueError("missing transport header")
        source_port, destination_port = transport.sport, transport.dport

    captured = packet.original
    return TrafficMetadata(
        interface=packet.sniffed_on,
        timestamp=float(packet.time),
        protocol=protocol,
        ip_protocol=ip_protocol,
        source_mac=ethernet.src,
        destination_mac=ethernet.dst,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        captured_bytes=len(captured) if captured else len(packet),
    )


def capture_traffic(
    interfaces, on_metadata, *, capture_filter=None, duration=None, opened_socket=None, on_packet=None,
):
    def handle_packet(packet):
        if on_packet is not None:
            on_packet(packet)
        try:
            metadata = read_metadata(packet)
        except (AttributeError, IndexError, TypeError, ValueError, Scapy_Exception):
            logger.debug("Skipping malformed packet on %s", getattr(packet, "sniffed_on", "?"))
            return
        if metadata is not None:
            on_metadata(metadata)

    options = {} if duration is None else {"timeout": duration}
    if opened_socket is None:
        options["iface"] = list(dict.fromkeys(interfaces))
    else:
        options["opened_socket"] = opened_socket
    started = monotonic() if duration is not None else None
    sniff(
        filter=capture_filter,
        prn=handle_packet,
        store=False,
        chainCC=True,
        **options,
    )
    if (started is None or monotonic() - started < duration
            or (opened_socket and any(socket.closed for socket in opened_socket))):
        raise OSError("capture ended unexpectedly")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", action="append", required=True, help="Gateway port to observe (repeatable)")
    parser.add_argument("--filter", help="Optional libpcap capture filter")
    parser.add_argument("--duration", type=int, help="Capture duration in seconds")
    args = parser.parse_args()
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")

    def write_metadata(metadata):
        print(json.dumps(asdict(metadata)), flush=True)

    try:
        capture_traffic(args.iface, write_metadata, capture_filter=args.filter, duration=args.duration)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, Scapy_Exception) as error:
        print(f"Traffic capture failed on {', '.join(args.iface)}: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
