# INDS-50 — Incident lifecycle and history

Incidents move between three statuses: `open`, `investigating` and `resolved`.
The administrator changes the status from the incident panel and can add an
optional note (max 300 characters). A resolved incident can be reopened.
Timestamps are kept on the incident (first seen, last seen, created, updated,
resolved) and every change is written to the audit log.

## History timeline

`GET /api/incidents/{id}/history` returns the audit events of one incident,
oldest first, with the administrator who did it (or none when INDS did it):

- `incident.created` and `incident.escalated` (detection, INDS-49)
- `incident.status_changed` with the optional note
- `ai_analysis.attached`
- `response_action.*` (approved, rejected, block applied, removal requested,
  block removed, cancelled, and gateway failures)

The incident panel shows it as a timeline at the bottom. Failed gateway
operations are shown in red.

## Historical incidents

`GET /api/incidents` filters on the server:

- `status`: `open`, `investigating`, `resolved`, or `active` (not resolved)
- `severity`
- `search`: part of an IP address or a rule name ("port scan" finds `PORT_SCAN`)
- `limit` (max 500) and `offset`

`GET /api/incidents/counts` returns the number of incidents in each status.
The Incidents page loads 50 incidents at a time with a "Load 50 more" button,
so old resolved incidents can always be reached.