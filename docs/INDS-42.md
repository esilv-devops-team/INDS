# INDS-42 — Capture traffic metadata

The gateway collector emits one JSON line per observed frame with the interface,
timestamp, protocol, source and destination MAC and IP addresses, TCP/UDP ports
when available, and captured frame size. Packet payloads are omitted.

On the Pi, install `gateway/requirements.txt` in the virtual environment and
run from the repo root. Replace `AP_PORT` with the AP-facing bridge port.

```sh
sudo .venv/bin/python -m gateway.traffic --iface AP_PORT
```

Use Ctrl+C to stop. The collector skips malformed packets and reports capture
failures to stderr. Use `--filter` to restrict capture further. Capturing on both
bridge ports can count the same forwarded frame twice.

Unit tests cover IPv4, IPv6, ARP, malformed packets, and capture errors. Live
capture on the Pi is pending.
