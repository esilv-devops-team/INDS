# INDS-46 — Abnormal traffic volume

`TRAFFIC_SPIKE` evaluates completed per-device windows from SQLite. It adds
upload and download, then compares the byte and packet rates with separate
limits. Exact matches pass. Partial startup windows are skipped and repeated
findings for the same device are suppressed during cooldown.

| Backend setting | Default |
| --- | --- |
| `INDS_TRAFFIC_SPIKE_ENABLED` | `1` |
| `INDS_TRAFFIC_SPIKE_WINDOW_MINUTES` | 1 |
| `INDS_TRAFFIC_SPIKE_BYTES_PER_MINUTE` | 104857600 (100 MiB) |
| `INDS_TRAFFIC_SPIKE_PACKETS_PER_MINUTE` | 100000 |
| `INDS_TRAFFIC_SPIKE_COOLDOWN_SECONDS` | 300 |

Settings take effect when monitoring starts. A finding in the backend log
contains the rule ID, device ID, UTC time, severity, thresholds, and measured
rates. High volume may reflect legitimate traffic. Tune limits against normal
guest use on the Pi.

Rules live in `detection/rules/` and share the contracts in `detection/base.py`.
Only `TRAFFIC_SPIKE` is registered in this story. Incident creation is handled
by INDS-49.
