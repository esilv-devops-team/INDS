# INDS-44 — Manage monitoring lifecycle

Start opens a capture socket on the AP-facing bridge port and runs device
discovery and traffic collection. Stop closes the run, discards any pending
batch, and closes the capture socket. SQLite retains the inventory, summaries,
and audit history. The Linux bridge continues forwarding independently.

On the Pi, use one backend process with the database migrated, gateway
dependencies installed, and raw capture permission. Set
`INDS_MONITOR_INTERFACE` to the AP-facing port and optionally
`INDS_MONITOR_AP_MAC` to exclude the access point from discovery. The managed
collector uses the bridge forwarding table to identify guest devices.

Use an administrator session for these API calls:

- `POST /api/system/monitoring/start`
- `POST /api/system/monitoring/stop`
- `GET /api/system/status`

Capture failures close the run and appear in the overview. A backend restart
closes interrupted runs and starts in OFF. The dashboard control belongs to
INDS-54.

For Pi validation, start monitoring with a guest connected, generate ordinary
traffic, and check the device and traffic totals in the dashboard. Stop
monitoring while the guest is still using the network. Verify that forwarding
continues, the totals stop changing, and the recorded history stays visible.
