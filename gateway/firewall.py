"""Provision the dedicated INDS bridge firewall on the gateway."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

TABLE = "inds_gateway"
BLOCK_SET = "blocked_macs"
NETWORK_DEVICES = Path("/sys/class/net")
INTERFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def render_policy(bridge, guest_port, router_port):
    interfaces = (bridge, guest_port, router_port)
    if any(not INTERFACE.fullmatch(name) for name in interfaces):
        raise ValueError("Use interface names of 1–15 letters, numbers, dots, underscores, or hyphens.")
    if len(set(interfaces)) != len(interfaces):
        raise ValueError("The bridge, guest port, and router port must be distinct.")

    return (
        f"create table bridge {TABLE}\n"
        f"add set bridge {TABLE} {BLOCK_SET} {{ type ether_addr; }}\n"
        f"add chain bridge {TABLE} forward {{ type filter hook forward priority 0; policy accept; }}\n"
        f'add rule bridge {TABLE} forward meta ibrname "{bridge}" meta obrname "{bridge}" '
        f'iifname "{guest_port}" oifname "{router_port}" ether saddr @{BLOCK_SET} counter drop\n'
        f'add rule bridge {TABLE} forward meta ibrname "{bridge}" meta obrname "{bridge}" '
        f'iifname "{router_port}" oifname "{guest_port}" ether daddr @{BLOCK_SET} counter drop\n'
    )


def verify_bridge(bridge, ports, root=NETWORK_DEVICES):
    bridge_path = root / bridge
    if not (bridge_path / "bridge").is_dir():
        raise ValueError(f"{bridge} is not an existing Linux bridge.")
    for port in ports:
        try:
            master = (root / port / "master").resolve(strict=True)
        except FileNotFoundError:
            master = None
        if master != bridge_path.resolve():
            raise ValueError(f"{port} is not a member of {bridge}.")


def run_policy(policy, *, check):
    command = ["nft"]
    if check:
        command.append("--check")
    command.extend(["--file", "-"])
    result = subprocess.run(command, input=policy, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError(result.stderr.strip() or f"nft exited with status {result.returncode}.")


def blocked_macs():
    result = subprocess.run(
        ["nft", "--json", "list", "set", "bridge", TABLE, BLOCK_SET],
        text=True, capture_output=True, timeout=10, check=True,
    )
    for entry in json.loads(result.stdout)["nftables"]:
        definition = entry.get("set")
        if definition and definition["name"] == BLOCK_SET and definition["type"] == "ether_addr":
            members = definition.get("elem", [])
            if all(isinstance(member, str) and MAC.fullmatch(member.lower()) for member in members):
                return {member.lower() for member in members}
    raise ValueError("Unexpected INDS firewall set definition.")


def set_block(mac, blocked):
    mac = mac.lower()
    if not MAC.fullmatch(mac) or mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        raise ValueError("The block target must be a unicast MAC.")
    if (mac in blocked_macs()) != blocked:
        verb = "add" if blocked else "delete"
        run_policy(f"{verb} element bridge {TABLE} {BLOCK_SET} {{ {mac} }}\n", check=False)
        if (mac in blocked_macs()) != blocked:
            raise ValueError("The gateway did not confirm the requested block state.")


def clear_blocks():
    if blocked_macs():
        run_policy(f"flush set bridge {TABLE} {BLOCK_SET}\n", check=False)
        if blocked_macs():
            raise ValueError("The INDS block set remains populated.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("render", "check", "install"))
    parser.add_argument("--bridge", default="br-inds")
    parser.add_argument("--guest-port", required=True)
    parser.add_argument("--router-port", required=True)
    args = parser.parse_args()

    try:
        policy = render_policy(args.bridge, args.guest_port, args.router_port)
        if args.command == "render":
            print(policy, end="")
            return 0
        verify_bridge(args.bridge, (args.guest_port, args.router_port))
        run_policy(policy, check=args.command == "check")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"INDS firewall {args.command} failed: {error}", file=sys.stderr)
        return 1

    print("INDS firewall policy validated." if args.command == "check" else "INDS firewall installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
