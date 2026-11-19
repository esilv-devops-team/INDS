# INDS-73 — Device investigation

Open **Devices** and select a device name or MAC address. Its profile shows
the IP, MAC, hostname when known, manufacturer, trust, and first and last
observation times. Recently seen means activity within the last five minutes.

**Traffic activity** shows upload and download trends, byte totals, and packet
counts for the last hour, 24 hours, or seven days. Recent rates use the last
five completed minutes of locally stored traffic summaries.

**Incident history** shows incidents linked to this device as their source.
Filter by status or select an incident to review its evidence and response.

Verified with API tests and an Edge walkthrough at desktop and mobile widths
using an isolated SQLite database.
