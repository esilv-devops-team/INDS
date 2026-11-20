# INDS-47 — Suspicious ARP changes

While monitoring is active, INDS checks ARP requests and replies against
administrator-configured IPv4-to-MAC bindings for stable devices such as the
router. Set `INDS_ARP_PROTECTED_BINDINGS` on the backend before starting
monitoring. Use comma-separated `IP=MAC` entries.

```sh
export INDS_ARP_PROTECTED_BINDINGS=192.0.2.1=02:00:00:00:00:01
```

Replace the example with bindings verified on your network. An empty setting
disables the rule. Conflicting claims generate a finding with the expected
and advertised MACs, frame source, and device ID if known. Repeated findings
from the same frame source are suppressed for five minutes. Unprotected DHCP
changes and ARP probes are ignored.

Findings are logged for investigation. Pi validation is pending.
