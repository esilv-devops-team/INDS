# INDS-75 - Configurable detection rules

Each detection rule has one row in the `detection_rules` table: an on/off
switch, a severity, a cooldown (how long repeated findings for the same device
are ignored) and its own thresholds. Migration `0003` creates the table with
these defaults:

| Rule | Severity | Settings |
| --- | --- | --- |
| `TRAFFIC_SPIKE` | Medium | `window_minutes` 1, `max_bytes_per_minute` 104857600, `max_packets_per_minute` 100000 |
| `ARP_SPOOFING` | High | `protected_bindings` {} (empty means the rule does nothing) |
| `PORT_SCAN` | Medium | `distinct_ports` 20, `window_seconds` 60 (used by INDS-76) |

All rules start enabled with a 300 second cooldown. Monitoring reads the rules
when it starts, so stop and start monitoring after a change. Invalid stored
values stop monitoring from starting with a clear error.

List or change rules from the repo root with the backend environment active:

```sh
python -m backend.manage_rules list
python -m backend.manage_rules set PORT_SCAN distinct_ports=30 severity=High
python -m backend.manage_rules set TRAFFIC_SPIKE enabled=false
python -m backend.manage_rules set ARP_SPOOFING 'protected_bindings={"192.168.1.1": "AA:BB:CC:DD:EE:FF"}'
```

Every change is validated (whole numbers in a safe range, known keys only,
unicast MAC and IPv4 host addresses) and written to the audit log as
`detection_rule.updated`. Administrators can read the rules with
`GET /api/detection/rules`. Editing from the dashboard is INDS-77.