# INDS — Remaining Work Tracker

## How to use this tracker

- Read this tracker and [TODO1.md](todo1.md) before starting a task. Reuse existing code. Record the change, tests actually run, and outstanding checks here after each task.
- Checked boxes cover only the scope described. Repository tests and Raspberry Pi acceptance are tracked separately. No AI providers, automatic blocking, or changes to the working gateway configuration in this phase.
- Baseline audited on 2026-11-23 at `main` commit `f4880de`. The prior run at this commit recorded 308 Python tests passed, one Windows skip for POSIX permissions, 97.11% coverage of `backend` and `detection`, and passing frontend lint/build and `pip check`. This tracker-only update reused that evidence.
- The [hardware report](../docs/INDS_Hardware_Network_Setup_Report.docx) verifies the routed gateway, DHCP, NAT, and client internet access. The deployed Pi uses ARM64 Debian 13, `eth0` upstream, `eth1` downstream at `192.168.50.1/24`, and an external AP. Operation ARES remains separate from INDS.

## Phase 1 — Routed discovery, traffic, and health (TODO1 A–B)

- [x] **Software — existing inventory.** MAC-based upsert, first/last seen, hostname, vendor and device API/detail are covered by [inventory](../tests/integration/test_device_inventory.py) and [investigation](../tests/integration/test_device_investigation.py) tests.
- [x] **Software — routed discovery and identity.** Managed `eth1` combines existing [Scapy observations](../gateway/discovery.py) with dnsmasq leases and reachable IPv4 neighbors, without a bridge FDB check on the routed path. The [inventory service](../backend/services/device_inventory.py) deduplicates by observed MAC, prioritizes address evidence, expires stale addresses, and handles confirmed IP reassignment. Migration `0004` records address provenance, expiry and recent activity separately. A lease alone does not establish presence. See [routed discovery tests](../tests/integration/test_routed_discovery.py).
- [x] **Software — existing monitoring.** Metadata parsing, minute traffic counters/history, monitoring lifecycle and OFF cleanup have [traffic](../tests/integration/test_traffic_activity.py), [lifecycle](../tests/integration/test_monitoring_lifecycle.py), and [OFF](../tests/integration/test_monitoring_off.py) tests. Packet payloads are outside persisted traffic summaries.
- [x] **Software — routed traffic attribution.** Same-batch reconciliation feeds the existing accumulator so a newly discovered device's first batch can count. A [lifecycle test](../tests/integration/test_monitoring_lifecycle.py) checks first-packet attribution and bypass of bridge commands with mocked capture. [Discovery documentation](../docs/gateway/discovery.md) describes the AP visibility limit.
- [x] **Software — routed health and topology baseline.** The [gateway API](../backend/services/gateway_health.py) reports LAN link and last capture status, keeps the SQLite check, and flags lease-file access separately from DHCP service health. The dashboard shows the LAN role and recent device activity. Direct DHCP service verification remains part of Pi acceptance.
- [x] **Pi verification — device discovery and live traffic.** Two downstream devices were discovered using DHCP leases and the neighbor table. The dashboard displayed MACs, IPs, DHCP evidence and timestamps. Live capture increased per-device upload, download and packet counters. Dashboard OFF preserved internet access through the Pi.

## Phase 2 — Detection, incidents, and risk (TODO1 C–E)

- [x] **Software — existing rules.** Traffic spike, ARP claim checks and port scan share the [detection engine](../detection/engine.py). Thresholds, enablement, cooldown, and evidence are implemented with [rule configuration](../tests/integration/test_detection_rules.py) and [detector tests](../tests/unit/). Rules produce findings for the incident pipeline.
- [x] **Software — existing rule regression checks.** Local tests exercise traffic window settlement, protected ARP claims, monitored port-scan findings, thresholds, evidence and cooldown. [Deployment plan](../docs/gateway/routed-deployment.md) records the current detection scope and the AP visibility limit. Live threshold tuning and positive/negative checks on `eth1` remain Pi acceptance items.
- [x] **Software — existing incident lifecycle.** Findings create incidents, repeats update occurrences, and open/investigating/resolved transitions have history. [Incident creation tests](../tests/integration/test_incident_creation.py) · [Incident history tests](../tests/integration/test_incident_history.py)
- [x] **Software — correlation and evidence.** [Grouping](../backend/services/incident_creation.py) bounds repeats to one run and a time window, preserves initial evidence and records each accepted repeat with its observed timestamp in the audit trail. Related incidents use verified inventory linkage or matching observed MAC and rule for unknown sources. The dashboard labels same-rule/target matches and displays related response history. IP reuse alone cannot create a link.
- [x] **Software — deterministic response policy.** [Policy](../backend/services/response_policy.py) reuses stored risk and severity, reports rule severity and LAN address confidence, and maps LOW/MEDIUM/HIGH/CRITICAL to observe, alert or an operator-approved proposal. Protected devices, unresolved identity and the configuration switch gate proposal eligibility. [Policy tests](../tests/unit/test_response_policy.py) cover all four levels.
- [x] **Pi verification — deployed rule settings inspected.** SQLite showed `PORT_SCAN` enabled, Medium, 20 distinct ports in 60 seconds, 300-second cooldown. `TRAFFIC_SPIKE` was enabled, Medium, 100 MiB/min or 100,000 packets/min, 300-second cooldown. `ARP_SPOOFING` was enabled, High, 300-second cooldown, with empty protected bindings. The monitoring, rule configuration and port-scan implementation were reviewed.
- [ ] **Pi verification — live detector and incident generation.** Validate `PORT_SCAN` first, then `TRAFFIC_SPIKE` and controlled `ARP_SPOOFING` with authorized input. No detector was exercised against live traffic in this session.
- [ ] **Pi verification — incident workflow.** Verify incident detail, original and repeat evidence, severity and risk, correlation, lifecycle transitions and audit history in the dashboard.

## Phase 3 — Response (TODO1 F)

- [x] **Software — existing decisions and history.** Approve/reject existing actions, record execution state, and reverse existing blocks. [API tests](../tests/integration/test_actions_api.py) use seeded proposals and mocked firewall operations.
- [x] **Software — proposal creation.** Operators create pending blocks from eligible incidents through the existing dashboard and actions API. The API records requester and reason, prevents competing blocks, and rechecks policy at approval. [API tests](../tests/integration/test_actions_api.py) cover proposal creation, competing requests, and approval.
- [x] **Software — routed enforcement with mocked operations.** [Executor](../gateway/firewall.py) uses the dedicated `inet inds_response` table and a LAN-to-WAN forwarding rule keyed by source MAC. It verifies set readback. Application approval requires matching inventory address and reachable IPv4 neighbor evidence and excludes configured infrastructure/management identities. Pi-local and AP-local traffic are outside the rule.
- [x] **Software — temporary blocks, reversal and restart.** Reused action expiry for kernel element timeouts and monitored audit reconciliation. Timed proposals can expire before approval, and monitoring stop/startup clear and reconcile the dedicated set with no automatic reapplication. [Tests](../tests/integration/test_actions_api.py) mock all firewall operations, including restart cleanup and expiry.
- [x] **Software — restricted routed execution.** The API uses a [Unix socket client](../gateway/firewall_client.py) and a separate [helper](../gateway/firewall_helper.py) with fixed verbs and INDS-owned table/set operations. Rejected requests cannot invoke nftables. The API service has capture permissions only. [Mocked tests](../tests/unit/test_firewall_helper.py) cover protected targets, arbitrary command rejection, and the expiry boundary. The helper units and capabilities require separate Linux and Pi verification.
- [ ] **Pi verification — response workflow.** Verify proposal, approval, rejection, cancellation and response history. Reversal remains open and requires a verified applied action.
- [ ] **Pi verification — live firewall enforcement.** Separate authorization required for block, kernel verification, reversal and expiry on an enrolled test device. Verify a second client, SSH, DHCP and NAT stay available. Enforcement remains disabled.
- **Deferred:** Rate limiting until an implementation and acceptance test are justified.

## Phase 4 — Dashboard (TODO1 G)

- [x] **Software — existing API-backed views.** Login, monitoring, devices and traffic, topology, gateway, incidents, responses and statistics share the current [React dashboard](../frontend/src/). Lint and build passed at baseline.
- [x] **Software — response and rule dashboard flows.** Existing views now show policy and address confidence, allow eligible proposals, and show their history and scheduled expiry. Gateway supports read-only rule review. Existing approve/reject and reversal controls consume the same action API. Browser acceptance remains open.
- [x] **Pi/browser verification — monitor-only workflow.** Windows access through the SSH tunnel, administrator login, authenticated API, monitoring ON/OFF, inventory, device traffic, topology and statistics passed. Topology showed the gateway, AP and two observed devices. Statistics showed about 7.1 MB collected, two active devices and per-device rankings.
- [ ] **Pi/browser verification — remaining workflow.** Verify incidents, responses, error and degraded states, and history as part of full non-AI acceptance.

## Phase 5 — Production deployment (TODO1 H)

- [x] **Software — existing foundation.** FastAPI, [SQLite and Alembic](../backend/database/), authentication and application shutdown/recovery logic are in place. Local tests cover initialization, migrations and monitoring recovery.
- [x] **Software — monitoring startup and recovery.** Migration `0005` persists the last operator ON/OFF choice. Enabled monitoring resumes after startup reconciliation and explicit OFF survives restart. Startup capture errors keep the API available and are audited and surfaced in the dashboard. Local tests cover ON, OFF and failed recovery without changing network services.
- [x] **Software — monitor-only deployment checklist.** [Routed deployment plan](../docs/gateway/routed-deployment.md#final-monitor-only-rollout-checklist) lists prerequisites, exact approval-gated commands, loopback browser access, validation, and rollback. [Systemd](../deploy/inds.service) and [Caddy](../deploy/Caddyfile.example) assets require target validation. Initial deployment keeps enforcement disabled and the firewall socket inactive.
- [x] **Pi verification — monitor-only deployment and backend restart.** Release `monitor-f4880de-20261123` ran on the Pi 4B (4 GB), Debian 13 ARM64. Offline ARM64 venv installation, migration `0005`, the dedicated `inds` user, `/etc/inds/inds.env`, startup via `inds.service` and FastAPI health passed. Backend restart preserved OFF and restored ON when configured. Inventory and timestamps persisted in both cases.
- [ ] **Pi verification — power-cycle and release readiness.** Verify full power-cycle recovery and boot persistence. Complete deployment hardening and final release-readiness checks.

## Phase 6 — Documentation and final validation (TODO1 I and deliverables)

- [x] **Software — baseline checks.** Backend suite, dependency check, frontend lint/build passed at `f4880de` as recorded above. [CI](../.github/workflows/ci.yml) runs tests and frontend checks. These checks do not validate the physical gateway.
- [x] **Software — routed discovery and correlation regression run.** Windows Python suite passed 314 tests with one POSIX-permissions skip and 96.73% coverage of `backend` and `detection`. Frontend lint/build passed. New checks cover lease-only presence, expiry and IP reassignment, first-batch traffic, routed health, incident identity/evidence and same-device history. Tests use local fixtures and mocked capture.
- [x] **Software — policy, response, and dashboard regression run.** Windows Python suite passed 321 tests with one POSIX-permissions skip and 96.37% coverage of `backend` and `detection`. Frontend lint and production build passed. Routed policy text rendered locally. Tests used mocks for nftables operations and checked proposal eligibility, pending approval, timed application, expiry, reconciliation and reversal.
- [x] **Software — recovery, helper, and evidence validation.** Full Windows suite passed 330 tests with one POSIX-permissions skip and 93.34% coverage across `backend`, `detection`, and `gateway`. Focused recovery, helper and incident history run passed 10 tests. Frontend lint and production build passed. Linux socket activation, target service privileges, and browser/Pi acceptance remain open.
- [ ] **Software — final validation.** Run focused regression tests after each change and rerun the full suite, lint/build and practical browser tests at the end. Record coverage, skips and limitations.
- [ ] **Documentation.** Update architecture and deployment instructions for the routed design. Document startup, updates, backup, recovery and rollback. Existing bridge instructions need clear scope.
- [ ] **Pi acceptance.** Record results for steps 1–17 in [TODO1.md](todo1.md), from DHCP and inventory through detection, approved action, reversal and restart.
- [ ] **Final report and handoff.** Include changed files, migrations, deployment, executed commands, test and hardware results, blockers and exact next steps.

### November 23, 2026 — Hardware validation checkpoint

- First monitor-only deployment validated on real hardware. Backend at `/opt/inds/current` returned `{"status":"ok","service":"inds-backend"}`. Extracted Caddy 2.6.2 ran as a temporary HTTPS reverse proxy. Windows reached `https://localhost:8443` through an SSH tunnel.
- Live discovery, traffic accounting, browser monitoring controls and backend restart recovery passed. The Pi remained healthy with low CPU and memory utilization during the session.
- Deployed rule configuration was inspected. Live detector, incident, response, firewall and full power-cycle acceptance remain open. Firewall enforcement remains disabled via `INDS_FIREWALL_ENABLED=0`.

## Phase 7 — AI (deferred)

- DeepSeek, structured provider assessments, and evaluation of Jev/Ollama are deferred. Keep the existing assessment storage/display boundary and keep enforcement independent of it.

## Proposed implementation order

1. Routed discovery and identity, then verify local fixtures and the inventory API.
2. Routed traffic attribution, monitoring lifecycle and health. Initial Pi verification completed November 23, 2026.
3. Rule evidence and thresholds, incident correlation and preservation, then deterministic risk policy.
4. Proposal creation, routed executor, temporary blocks and restart reconciliation, with mocked firewall tests.
5. Finish dashboard integration using the existing views and APIs.
6. Complete remaining Pi acceptance, power-cycle recovery, deployment hardening and final release validation.

**Next task:** Controlled `PORT_SCAN` detector validation on the authorized Pi test setup. Verify incident creation and recorded evidence while enforcement stays disabled.

## Blockers and approvals

- **Monitor-only deployment verified.** Further Pi acceptance starts with controlled `PORT_SCAN` detection. Keep DHCP, NAT, SSH and routed connectivity operational during all checks.
- **Pi changes require explicit approval:** packages, system services, privileged permissions or execution, network service restarts, reboot, and firewall changes. Present commands, effects and rollback before requesting approval. Preserve NetworkManager, dnsmasq, host routing/NAT and SSH configuration.
- **Live firewall testing requires separate approval:** identify the exact enrolled target, expected restriction, rules, rollback, and protections for SSH, DHCP, NAT and other clients.
