"""Speak the fixed routed firewall protocol over a local Unix socket."""

import os
import socket


def request(command):
    path = os.environ.get("INDS_FIREWALL_SOCKET", "/run/inds-firewall.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(35)
        connection.connect(path)
        connection.sendall(command.encode("ascii") + b"\n")
        with connection.makefile("rb") as response:
            if response.readline(16) != b"OK\n":
                raise OSError("Restricted firewall helper did not confirm the operation.")


def set_block(mac, blocked, *, timeout_seconds=None):
    if blocked:
        if timeout_seconds is not None and not 0 < timeout_seconds <= 3600:
            raise ValueError("The temporary block has expired or has an invalid timeout.")
        request(f"block {mac} {timeout_seconds if timeout_seconds is not None else 0}")
    else:
        request(f"unblock {mac}")


def clear_blocks():
    request("clear")
