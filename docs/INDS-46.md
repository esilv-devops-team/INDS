# INDS-46 - Abnormal traffic volume

`TRAFFIC_SPIKE` evaluates completed per-device windows from SQLite. It adds
upload and download, then compares the byte and packet rates with separate
limits. Exact matches pass. Partial startup windows are skipped and repeated
findings for the same device are suppressed during cooldown.

The rule is configured in the `TRAFFIC_SPIKE` row of the detection rules
(see [INDS-75](INDS-75.md)): `window_minutes` 1, `max_bytes_per_minute`
104857600 (100 MiB), `max_packets_per_minute` 100000, severity Medium and a
300 second cooldown.

Settings take effect when monitoring starts. A finding in the backend log
contains the rule ID, device ID, UTC time, severity, thresholds, and measured
rates. High volume may reflect legitimate traffic. Tune limits against normal
guest use on the Pi.

Rules live in `detection/rules/` and share the contracts in `detection/base.py`.
Only `TRAFFIC_SPIKE` is registered in this story. Incident creation is handled
by INDS-49.