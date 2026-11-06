import requests
from scapy.all import ARP, BOOTP, DHCP, IP, TCP, UDP, Ether
from scapy.utils import mac2str

from gateway import discovery
from gateway.discovery import add_device, is_real_mac, read_fdb, read_packet, send_devices


def make_dhcp(mac, options, ciaddr="0.0.0.0"):
    packet = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac2str(mac), ciaddr=ciaddr)
        / DHCP(options=options + ["end"])
    )
    return Ether(bytes(packet))


def test_dhcp_request():
    packet = make_dhcp("00:11:22:33:44:55", [
        ("message-type", "request"),
        ("requested_addr", "192.168.1.23"),
        ("hostname", "firas-laptop"),
    ])
    assert read_packet(packet) == {"mac": "00:11:22:33:44:55", "ip": "192.168.1.23", "hostname": "firas-laptop"}


def test_dhcp_without_hostname():
    packet = make_dhcp("00:11:22:33:44:55", [("message-type", "discover")])
    assert read_packet(packet) == {"mac": "00:11:22:33:44:55", "ip": None, "hostname": None}


def test_dhcp_renew_uses_current_ip():
    packet = make_dhcp("00:11:22:33:44:55", [("message-type", "request")], ciaddr="192.168.1.40")
    assert read_packet(packet)["ip"] == "192.168.1.40"


def test_arp():
    packet = Ether(bytes(Ether(src="aa:bb:cc:11:22:33") / ARP(hwsrc="aa:bb:cc:11:22:33", psrc="192.168.1.50", pdst="192.168.1.1")))
    assert read_packet(packet) == {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.50", "hostname": None}


def test_arp_probe_has_no_ip():
    packet = Ether(bytes(Ether(src="00:11:22:33:44:55") / ARP(hwsrc="00:11:22:33:44:55", psrc="0.0.0.0", pdst="192.168.1.23")))
    assert read_packet(packet)["ip"] is None


def test_other_packets_ignored():
    packet = Ether(bytes(Ether(src="00:11:22:33:44:55") / IP(src="192.168.1.23", dst="1.1.1.1") / TCP(dport=443)))
    assert read_packet(packet) is None


def test_is_real_mac():
    assert is_real_mac("00:11:22:33:44:55")
    assert not is_real_mac("FF:FF:FF:FF:FF:FF")
    assert not is_real_mac("01:00:5E:00:00:FB")
    assert not is_real_mac("00:00:00:00:00:00")


def test_add_device_keeps_known_values():
    devices = {}
    add_device(devices, {"mac": "00:11:22:33:44:55", "ip": "192.168.1.23", "hostname": "laptop"})
    add_device(devices, {"mac": "00:11:22:33:44:55", "ip": "192.168.1.24", "hostname": None})
    add_device(devices, None)
    assert devices == {"00:11:22:33:44:55": {"mac": "00:11:22:33:44:55", "ip": "192.168.1.24", "hostname": "laptop"}}


def test_read_fdb():
    output = (
        "aa:bb:cc:11:22:33 dev eth1 master br-inds\n"
        "dc:a6:32:00:00:01 dev eth1 vlan 1 master br-inds permanent\n"
        "33:33:00:00:00:01 dev eth1 self permanent\n"
    )
    assert read_fdb(output) == {"AA:BB:CC:11:22:33"}


class FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"received": 1, "new": 1}


def test_send_devices(monkeypatch):
    sent = []

    def fake_post(url, json, timeout):
        sent.append(json)
        return FakeResponse()

    monkeypatch.setattr(discovery.requests, "post", fake_post)
    devices = {"00:11:22:33:44:55": {"mac": "00:11:22:33:44:55", "ip": None, "hostname": None}}
    assert send_devices(devices)
    assert sent == [{"observations": [{"mac": "00:11:22:33:44:55", "ip": None, "hostname": None}]}]


def test_send_devices_backend_down(monkeypatch):
    def fake_post(url, json, timeout):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(discovery.requests, "post", fake_post)
    assert not send_devices({"00:11:22:33:44:55": {"mac": "00:11:22:33:44:55", "ip": None, "hostname": None}})