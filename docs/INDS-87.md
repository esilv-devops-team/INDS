# INDS-87 - Live Network page

New "Live Network" page in the sidebar (`/live`,
`frontend/src/pages/LiveNetwork.jsx`). It shows the real traffic of the
monitored port live, like Wireshark, and what INDS does with it.

## Layout

- The monitoring panel (ON / OFF) on top, so the whole demo happens on one page.
- A mode banner:
  - INDS OFF: nothing captured, button "Watch traffic without INDS".
  - Watching without INDS: packets only displayed, nothing detected, analysed
    or blocked, with the time left and a "Stop watching" button.
  - INDS ON: every packet goes through detection.
- Four counters: packets per second, packets in view, packets from devices
  with an incident, packets dropped by INDS.
- The packet list: number, time (with milliseconds), source, destination,
  protocol, length and info. Rows are coloured by protocol (TCP, UDP, ARP,
  ICMP), rows captured without INDS are dimmed, rows from a device with an
  incident are orange with the incident number, and dropped rows are red with
  a DROPPED tag. The list follows new packets, Pause freezes it, the bin
  button clears it, and the filter works on addresses, MACs, protocol and
  info.
- Clicking a row shows its headers like Wireshark (frame, Ethernet, IP or ARP,
  TCP or UDP with flags) and what INDS did with it.
- On the side: packets per second over 60 seconds, the busiest source
  addresses, and a feed of incidents, AI analyses and responses that links to
  each incident.

The page asks `GET /api/live` for new packets every second (INDS-86) and
`GET /api/live/events` every 2 seconds. Only real data from the gateway is
shown.

## New API

`GET /api/live/events?after=<id>` (administrator): audit events linked to an
incident for the feed (`incident.created`, `incident.escalated`,
`ai_analysis.attached`, `ai_analysis.failed`, `response_action.proposed`,
`approved`, `rejected`, `applied`, `cleared`). Without `after` it returns the
last 20, oldest first; with `after` the newer ones (max 50).

## Presentation flow

1. INDS OFF, click "Watch traffic without INDS".
2. Attack from the test device (for example a port scan of the Pi): the scan
   is visible packet by packet, nothing else happens.
3. Turn monitoring ON in the panel on top.
4. Run the attack again: rows turn orange with the incident number, the feed
   shows the incident, then the AI analysis and the block proposal.
5. Approve the block from the incident: the feed shows the block and the
   attacker's packets turn red with DROPPED.

## Tests

`tests/integration/test_live_api.py::test_events_feed`. The page itself is
checked with lint, build and by hand.
