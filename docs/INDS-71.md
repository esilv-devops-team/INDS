# INDS-71 — Dashboard updates

While the dashboard is visible, monitoring status, device inventory, and
incidents refresh about every five seconds. Recent device traffic rates
refresh every ten seconds, and historical charts every twenty seconds.

Views using the same API URL share one request. Refresh pauses while the tab
is hidden or the browser is offline. Returning to the tab or reconnecting
refreshes it immediately. On a temporary failure, the last good data stays
visible and the top bar flags delayed status updates.

Verified in Edge with changing monitoring data, shared requests, hidden tabs,
reconnects, temporary API errors, and expired sessions.
