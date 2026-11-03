# Gateway verification (INDS-36)

Status: not run on hardware. Record date, commit, OS, adapter, NetworkManager
version, wiring, client, and results in ignored `gateway/local/`. Commit only a
sanitized acceptance summary. Do not record customer traffic or credentials.

## Forwarding acceptance

| Check | Expected evidence |
| --- | --- |
| Physical path | AP has one uplink through the two-port Pi; no bypass |
| Bridge membership | `bridge link show` lists both intended ports on `br-inds` |
| Client addressing | A newly connected guest receives router-issued DHCP settings |
| Client connectivity | Client reaches router, resolves a hostname, and opens HTTPS sites |
| Management | Pi is reachable at its recorded bridge management address |
| IPv6, if supplied upstream | Client IPv6 connectivity survives insertion of the bridge |
| Application absent/stopped | Client connectivity works with backend/detection not running |
| Application failure | When a detection service exists, deliberately terminate it and repeat client checks |
| Reboot | Both ports rejoin the bridge; DHCP, DNS, and browsing recover without application startup |

Run client checks from a device on the guest AP. Use continuous client probes
during application stop/failure tests and record packet loss and interruptions.
A reboot itself interrupts connectivity; the reboot check verifies recovery,
not uninterrupted operation during power loss. If the detection service does not
exist yet, mark its crash test **pending**, not passed.

## Performance baseline

Compare the same client, AP, router, test endpoint, and link conditions:

1. AP connected directly to router.
2. AP connected through the Pi with no INDS collection/enforcement.
3. Later, the same setup with monitoring ON, then under controlled detection/AI load.

Use a local wired test server upstream of the Pi where possible to separate
gateway overhead from ISP variation. Measure both upload/download, repeated
latency samples, packet loss, and Pi CPU/memory. Use identical test durations and
repeat at least three times. Internet speed tests are supplementary.

| Metric | Direct | Pi forwarding only | Monitoring ON (future) |
| --- | --- | --- | --- |
| Download throughput | Pending | Pending | Pending |
| Upload throughput | Pending | Pending | Pending |
| Latency median / p95 | Pending | Pending | Pending |
| Packet loss | Pending | Pending | Pending |
| Pi CPU / memory | N/A | Pending | Pending |

Agree numerical throughput/latency acceptance limits before claiming the
performance requirement is met. This package makes no throughput guarantee.

AP-local device-to-device traffic may never cross the Pi. Record this visibility
limit instead of claiming complete monitoring of every guest interaction.
