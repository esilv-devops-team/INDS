# INDS-72 — Security response visualization

Open **Responses** to review recorded blocks and rate limits. Filter by
approval or gateway execution, then expand a record for its target, reason,
operator, timestamps, and any execution error.

Approval and execution appear separately. An approved response can still
show **Not applied**. **Reported active** reflects the last recorded gateway
execution state. The incident view shows the same states.

Use the incident and device links to investigate an action, or open
**Response history** from a device profile to see its linked actions.

Verified with API tests and an Edge walkthrough at desktop and mobile widths
using recorded test actions in SQLite.
