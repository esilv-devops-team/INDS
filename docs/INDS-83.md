# INDS-83 - Incident context for AI analysis

Before an incident goes to DeepSeek, INDS turns it into one clean JSON object
with `build_context(session, incident)` in `backend/services/ai_context.py`.
The same object is saved in `ai_analyses.input_summary_json`, so we can always
see exactly what was sent.

## What is in the context

- `threat_type`, `severity`, `risk_score`, `status`, `occurrences`,
  `first_seen_at`, `last_seen_at`
- `source` and `target`
- `evidence`: the detection evidence of the rule (ports, limits, measured values)
- `device`: vendor, trusted or not, first seen, how long it was known before the
  incident, new device (< 60 min), other open incidents
- `traffic`: totals of the device from 10 minutes before the incident until its
  last finding, and its usual traffic per minute over the 24 hours before
- `previous_incidents`: the last 5 older incidents of the same device

No packets are sent, only aggregated values.

## Private data

IP addresses, MAC addresses and hostnames never leave INDS (FR-41). Every field
ending in `_ip` or `_mac` is replaced by a reference:

| Address | Sent as |
|---|---|
| known device (by MAC or current IP) | `device-<id>` |
| access point (`INDS_MONITOR_AP_MAC`) | `access point` |
| unknown private IP | `lan host` |
| public IP | `external host` |
| unknown MAC | `unknown device` |
| `multiple` | `multiple targets` |

For example ARP spoofing evidence `sender_ip`, `expected_mac` and `claimed_mac`
become `sender`, `expected` and `claimed`, so the AI still sees which device
claims the address of which device.

## Tests

`tests/integration/test_ai_context.py` covers port scan, ARP spoofing and
traffic spike incidents, incidents without a device, previous incidents and
every kind of address, and checks that no IP, MAC or hostname appears in the
context.
