# INDS-86 - Live packet activity

INDS keeps the last packets seen on the monitored port in memory so the
dashboard can show the network live, like Wireshark
(`backend/services/live_traffic.py`).

## What is kept

Only header summaries of the last 500 packets: number, time, source and
destination MAC, IP and port, protocol, TCP flags, length and a short info
text (for example `51000 → 22 [SYN]` or `Who has 192.168.50.1? Tell
192.168.50.66`). Payloads are never read. Nothing is written to the database
and everything is lost when the service restarts. The number of packets per
second is kept for the last 60 seconds.

## Two modes

| Mode | When | What happens |
|---|---|---|
| `protect` | monitoring is ON | the existing capture also fills the live view, no second capture |
| `watch` | monitoring is OFF and the administrator starts the live view | a display-only capture: nothing is detected, saved, analysed or blocked |
| `off` | monitoring is OFF and no live view | nothing is captured |

The watch-only capture stops when nobody asked for packets for 2 minutes,
after 10 minutes, when the administrator stops it, and when monitoring is
turned ON. Monitoring always comes first: an error in the live view never
stops detection.

## Marks

Only packets captured while INDS is ON get marks:

- `incident_id`: the source device has an open incident in the current
  monitoring run.
- `dropped`: the source device has an active block on the gateway and the
  packet arrived after the block was applied. The Pi still sees these packets
  on `eth1`, the firewall drops them before they reach the internet.

## API (administrator only)

- `GET /api/live?after=<number>`: mode, interface, seconds left for the watch
  capture, number of the last packet, the new packets (max 200 per call) and
  the packets per second of the last 60 seconds. Polling it keeps the watch
  capture alive.
- `POST /api/live/watch`: start the watch-only capture. 409 when INDS is ON,
  503 without `INDS_MONITOR_INTERFACE` or when the capture cannot be opened.
- `DELETE /api/live/watch`: stop it.

## Tests

`tests/unit/test_live_traffic.py` (info text, buffer limit, packets per
second, watch capture start, stop, timeouts and errors) and
`tests/integration/test_live_api.py` (login, modes, marks, errors).
`test_monitoring_creates_incidents` checks that the monitoring capture fills
the live view.
