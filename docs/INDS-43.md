# INDS-43 — Monitor device activity and traffic rates

The backend stores one-minute byte and packet totals in the Pi's SQLite
database. It matches frames to known devices by MAC address, counts traffic
from each device's perspective, and refreshes its last-seen time.

With the database migrated and a monitoring run active, capture and ingest one
batch from the repo root on the Pi. Replace `AP_PORT` with the AP-facing port.

```sh
set -o pipefail
sudo .venv/bin/python -m gateway.traffic --iface AP_PORT --duration 10 |
  .venv/bin/python -m backend.ingest_traffic
```

The Statistics page uses these totals. The authenticated
`GET /api/devices/{id}/traffic` endpoint gives upload and download in bits per
second over the last five completed minutes. Submit each capture batch once.

INDS-44 owns starting and stopping monitoring. This command handles a single
batch. Integration tests passed with SQLite. Live capture on the Pi is pending.
