"""Serve one validated request from the systemd-owned firewall socket."""

import logging
import os
import re
import sys

from gateway import firewall

logger = logging.getLogger(__name__)
BLOCK = re.compile(r"block ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) (0|[1-9][0-9]{0,3})")
UNBLOCK = re.compile(r"unblock ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")


def run_request(request, protected):
    if request == "clear":
        firewall.clear_blocks(routed=True)
        return
    if match := BLOCK.fullmatch(request):
        mac, duration = match.groups()
        if not protected or mac.lower() in protected:
            raise ValueError("Missing protection configuration or protected target.")
        firewall.set_block(mac, True, routed=True, timeout_seconds=int(duration) or None)
    elif match := UNBLOCK.fullmatch(request):
        firewall.set_block(match[1], False, routed=True)
    else:
        raise ValueError("Unsupported firewall request.")


def serve(source, reply, protected):
    try:
        line = source.readline(64)
        if not line.endswith(b"\n"):
            raise ValueError("Invalid firewall request length.")
        run_request(line[:-1].decode("ascii"), protected)
    except (OSError, ValueError, TypeError, KeyError, firewall.subprocess.SubprocessError):
        logger.exception("Restricted firewall request failed")
        reply.write(b"ERROR\n")
    else:
        reply.write(b"OK\n")
    reply.flush()


def main():
    values = [
        os.environ.get("INDS_MONITOR_AP_MAC", "").lower().strip(),
        *[value.lower().strip() for value in os.environ.get("INDS_PROTECTED_MACS", "").split(",")],
    ]
    protection = set(values) if len(set(values)) >= 2 and all(firewall.MAC.fullmatch(value) for value in values) else set()
    serve(sys.stdin.buffer, sys.stdout.buffer, protection)


if __name__ == "__main__":
    main()
