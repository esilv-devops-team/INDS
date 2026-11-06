import argparse
import subprocess

import requests
from scapy.all import ARP, BOOTP, DHCP, sniff
from scapy.utils import str2mac

API_URL = "http://127.0.0.1:8000/api/devices/observations"
CAPTURE_FILTER = "arp or udp port 67 or udp port 68"


def is_real_mac(mac):
    if mac == "00:00:00:00:00:00":
        return False
    first_byte = int(mac[:2], 16)
    return first_byte % 2 == 0


def read_packet(packet):
    if packet.haslayer(DHCP) and packet[BOOTP].op == 1:
        mac = str2mac(packet[BOOTP].chaddr[:6]).upper()
        ip = None
        hostname = None
        if packet[BOOTP].ciaddr != "0.0.0.0":
            ip = packet[BOOTP].ciaddr
        for option in packet[DHCP].options:
            if option[0] == "requested_addr":
                ip = option[1]
            if option[0] == "hostname":
                hostname = option[1].decode(errors="ignore")
    elif packet.haslayer(ARP):
        mac = packet[ARP].hwsrc.upper()
        ip = packet[ARP].psrc
        if ip == "0.0.0.0":
            ip = None
        hostname = None
    else:
        return None

    if not is_real_mac(mac):
        return None
    return {"mac": mac, "ip": ip, "hostname": hostname}


def add_device(devices, info):
    if info is None:
        return
    old = devices.get(info["mac"], {})
    devices[info["mac"]] = {
        "mac": info["mac"],
        "ip": info["ip"] or old.get("ip"),
        "hostname": info["hostname"] or old.get("hostname"),
    }


def read_fdb(output):
    macs = set()
    for line in output.splitlines():
        if line and "permanent" not in line:
            macs.add(line.split()[0].upper())
    return macs


def macs_on_port(port):
    result = subprocess.run(["bridge", "fdb", "show", "brport", port], capture_output=True, text=True)
    return read_fdb(result.stdout)


def send_devices(devices, url=API_URL):
    try:
        response = requests.post(url, json={"observations": list(devices.values())}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as error:
        print("could not send devices:", error)
        return False
    print("sent", len(devices), "devices,", response.json()["new"], "new")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--ignore", nargs="*", default=[])
    parser.add_argument("--bridge-port", action="store_true")
    parser.add_argument("--api", default=API_URL)
    args = parser.parse_args()
    ignored = [mac.upper() for mac in args.ignore]

    print("discovery started on", args.iface)
    devices = {}
    try:
        while True:
            packets = sniff(iface=args.iface, filter=CAPTURE_FILTER, timeout=args.interval, chainCC=True)
            for packet in packets:
                add_device(devices, read_packet(packet))

            for mac in ignored:
                devices.pop(mac, None)
            if args.bridge_port:
                guests = macs_on_port(args.iface)
                devices = {mac: d for mac, d in devices.items() if mac in guests}

            if devices and send_devices(devices, args.api):
                devices = {}
    except KeyboardInterrupt:
        print("discovery stopped")


if __name__ == "__main__":
    main()