# INDS-47 — Suspicious ARP changes

While monitoring is active, INDS checks ARP requests and replies against
administrator-configured IPv4-to-MAC bindings for stable devices such as the
router. Set them in the `ARP_SPOOFING` detection rule (see [INDS-75](INDS-75.md))
before starting monitoring:

```sh
python -m backend.manage_rules set ARP_SPOOFING 'protected_bindings={"192.0.2.1": "02:00:00:00:00:01"}'
```

Replace the example with bindings verified on your network. An empty
`protected_bindings` disables the rule. Conflicting claims generate a finding with the expected
and advertised MACs, frame source, and device ID if known. Repeated findings
from the same frame source are suppressed for five minutes. Unprotected DHCP
changes and ARP probes are ignored.

Findings are logged for investigation. Pi validation is pending.