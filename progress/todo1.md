# INDS — Complete Non-AI Implementation, Raspberry Pi Integration & Deployment

You are the lead software engineer responsible for completing the existing **INDS (Intelligent Network Detection & Response System)** project.

We have finished the initial hardware setup and conducted a full repository audit. We are now moving into implementation and deployment.

## PRIMARY OBJECTIVE

**Complete the entire functional INDS system, excluding AI integration.**

By the end, INDS should be able to:

1. Run independently on our Raspberry Pi 4.
2. Discover devices connected through our external Wi-Fi access point.
3. Identify and maintain an inventory of connected devices.
4. Continuously monitor device network activity.
5. Detect suspicious behavior using deterministic security rules.
6. Create structured incidents containing supporting evidence.
7. Correlate incidents with relevant device history.
8. Assign deterministic severity and risk classifications.
9. Display devices, traffic, incidents, and decisions in the dashboard.
10. Propose appropriate security responses.
11. Allow administrators to approve or reject actions.
12. Safely block or temporarily restrict individual devices.
13. Reverse or automatically expire temporary blocks.
14. Maintain comprehensive audit logs.
15. Recover safely after application or Pi restarts.
16. Start automatically when the Raspberry Pi boots.
17. Support future AI integration without requiring architectural changes.

**DO NOT implement DeepSeek, Jev, Ollama, or any other AI provider during this phase.**

However, preserve a clean, provider-independent interface for future AI assessments.

---

# 1. FIRST: Understand the Existing Project

Read the entire repository and the following document:

`docs/INDS_Hardware_Network_Setup_Report.docx`

Also review the previous project audit if it exists in the repository.

Do not assume that the hardware report means the INDS application is already deployed.

Do not rewrite existing working components unnecessarily.

Reuse the current:

- FastAPI backend
- SQLite database
- SQLAlchemy and Alembic migrations
- Scapy packet monitoring
- Detection engine
- Existing detection rules
- Incident management
- Response-action lifecycle
- Authentication
- React/Vite dashboard
- Existing tests and CI/CD

Before modifying anything, inspect the current Git branch, working tree, application entry points, configuration, and deployment assumptions.

Preserve all existing user changes and untracked files.

---

# 2. Actual Raspberry Pi Hardware Architecture

Our real, verified hardware topology is:

```text
Internet
   |
Existing Router
   |
   | Ethernet
   |
Raspberry Pi 4 Model B (4 GB)
   |
   | eth0 — WAN
   | DHCP from existing router
   |
   | Linux IPv4 Routing + NAT
   |
   | eth1 — LAN
   | 192.168.50.1/24
   |
External Wi-Fi Access Point
   |
   +-- Phone
   +-- Laptop
   +-- IoT Devices
```

Operating system:

- Raspberry Pi OS Lite 64-bit
- Debian 13 (trixie)
- ARM64
- NetworkManager
- dnsmasq
- nftables

Existing network configuration:

**WAN**
- Interface: `eth0`
- IP assigned through upstream DHCP
- Previously observed: `192.168.0.19`

**LAN**
- Interface: `eth1`
- Static IP: `192.168.50.1/24`
- USB Ethernet adapter using `rndis_host`

**DHCP**
- Service: `dnsmasq`
- Range: `192.168.50.100–192.168.50.200`
- Gateway: `192.168.50.1`
- DNS: `1.1.1.1`, `8.8.8.8`

**NAT and forwarding**
- IPv4 forwarding enabled
- nftables NAT table: `ip inds_nat`
- nftables forwarding table: `inet inds_filter`

Relevant configuration files:

- `/etc/dnsmasq.d/inds.conf`
- `/etc/nftables.conf`
- `/etc/sysctl.d/99-inds-gateway.conf`

The hardware gateway has already been tested successfully.

A phone connected through the external access point, received DHCP configuration, and accessed the internet with mobile data disabled.

## CRITICAL ARCHITECTURAL REQUIREMENT

**Our Pi uses a ROUTED network, NOT a Linux bridge.**

The previous audit found that the application still depends on:

- `bridge fdb show brport` for device membership
- Bridge-oriented gateway health checks
- nftables bridge-family firewall enforcement

These assumptions are incompatible with our actual deployment.

Adapt the software to the existing routed topology.

**Do not convert the Pi to bridge mode.**

---

# 3. Phase A — Device Discovery & Identity

Complete the device discovery system.

Requirements:

- Read confirmed dnsmasq DHCP leases.
- Read Linux neighbor/ARP observations.
- Integrate existing Scapy DHCP/ARP observations.
- Support the actual `eth1` LAN interface.
- Remove bridge-FDB membership as a mandatory discovery condition.
- Reconcile IP and MAC observations.
- Maintain device first-seen and last-seen timestamps.
- Track device online/offline status using defensible evidence.
- Support randomized MAC addresses.
- Avoid assuming a MAC address permanently identifies a physical device.
- Record the source and reliability of identity evidence.
- Prevent incorrect attribution when IP addresses are reassigned.
- Deduplicate observations.
- Handle disconnected devices and stale DHCP leases.
- Update device inventory APIs and dashboard views.

Do not treat an active DHCP lease alone as proof that a device is currently online.

**Acceptance test:** A real phone connected to the access point appears in the INDS inventory with the correct current IP/MAC and observable activity.

---

# 4. Phase B — Traffic Monitoring

Complete the existing Scapy monitoring pipeline.

Requirements:

- Capture relevant LAN traffic on `eth1`.
- Correctly attribute traffic to known devices.
- Record packet and byte counters.
- Maintain traffic history.
- Support configurable observation windows.
- Handle IPv4 traffic reliably.
- Avoid duplicate counting.
- Handle monitoring restarts and failures.
- Implement clear monitoring ON/OFF behavior.
- Ensure disabling monitoring does not disable routing, DHCP, NAT, or essential firewall services.
- Do not capture or persist unnecessary application payloads.
- Display meaningful traffic statistics in the dashboard.

Check whether capturing on `eth1` alone provides sufficient information for all existing rules. If not, document the limitation and implement an appropriate non-disruptive solution.

**Acceptance test:** Browse the internet from a connected phone and observe its network activity in the INDS dashboard.

---

# 5. Phase C — Detection Engine

Preserve and complete the existing deterministic detection system.

Existing rules:

- `PORT_SCAN`
- `ARP_SPOOFING`
- `TRAFFIC_SPIKE`

Requirements:

- Validate the three rules against actual monitored traffic.
- Preserve configurable thresholds.
- Support rule enable/disable controls.
- Record the exact evidence that triggered each rule.
- Implement appropriate cooldown and deduplication.
- Avoid excessive incident creation.
- Distinguish normal activity from suspicious activity as reliably as possible.
- Tune default thresholds conservatively.
- Avoid interpreting every traffic spike as an attack.
- Ensure rules do not block devices directly.

Review additional detection rules already planned in the project.

Implement additional rules only where the available telemetry supports reliable detection. Do not claim to detect attacks that the system cannot actually observe.

Document unsupported detection categories.

**Acceptance test:** Controlled, authorized test activity produces the expected finding and incident without disrupting unrelated clients.

---

# 6. Phase D — Incident Management & Correlation

Complete the incident pipeline.

Each incident should include:

- Incident ID
- Detection rule
- Initial severity
- Timestamps
- Device reference
- Source and destination evidence where available
- Relevant traffic statistics
- Detection thresholds
- Evidence and observation window
- Related incident references
- Current incident status
- Risk assessment
- Proposed response
- Response history
- Audit history

Implement incident correlation using:

- Reliable device identity
- Repeated detections
- Relevant time windows
- Shared behavioral patterns
- Previous incident history
- Existing response history

Avoid correlating unrelated devices solely because they reused the same IP address.

Preserve original evidence and distinguish it from later analysis.

Support:

- Open
- Investigating
- Resolved

Maintain accurate incident histories and avoid duplicate incident floods.

**Acceptance test:** A detected rule creates an incident, repeated related findings update or correlate correctly, and the incident appears in the dashboard.

---

# 7. Phase E — Deterministic Risk & Policy Engine

Implement a provider-independent decision engine.

For now, it must work **WITHOUT AI**.

Use:

- Rule severity
- Detection evidence
- Repeated findings
- Device history
- Identity reliability
- Protected-device status
- Configured administrator policy

Separate:

1. Detection severity
2. Evidence confidence
3. Final risk classification
4. Authorized response policy

Risk categories:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Default behavior:

**LOW**
- Record incident.
- Continue monitoring.

**MEDIUM**
- Create an alert.
- Continue monitoring.

**HIGH**
- Create a high-priority alert.
- Propose a response for administrator approval.

**CRITICAL**
- Create an urgent alert.
- Propose temporary containment.
- Require administrator approval by default.

Design an optional automatic-containment policy for future use, but keep automatic blocking disabled by default.

Do not enable automatic blocking merely because a numeric score exceeds a threshold.

Require independent safeguards before any future autonomous enforcement.

Risk classifications must be explainable and supported by deterministic evidence.

Create a clean interface through which a future AI provider can supply a structured assessment without controlling firewall execution directly.

**Acceptance test:** Known synthetic incidents produce deterministic, testable risk decisions and permitted response proposals.

---

# 8. Phase F — Response Engine & Firewall Enforcement

The previous audit found two major blockers:

1. No production path to create a response proposal.
2. Existing enforcement targets a Linux bridge instead of our routed LAN.

Fix both.

## Response actions

Support:

- Observe
- Alert
- Propose block
- Approve block
- Reject block
- Execute block
- Unblock
- Temporary block with expiration
- Automatic expiration and reversal

Rate limiting may be implemented if a reliable, testable solution fits the existing architecture. Otherwise, document it as a deferred capability rather than pretending it works.

## Firewall requirements

- Use nftables compatible with our routed `eth1` → `eth0` gateway.
- Keep INDS response rules separate from essential gateway configuration.
- Do not overwrite or flush unrelated nftables tables or chains.
- Never block the upstream router.
- Never block the Pi's management interface.
- Protect the administrator's management path.
- Validate device identity before enforcement.
- Prevent duplicate or contradictory actions.
- Verify actual kernel firewall state.
- Record execution results.
- Support reliable reversal.
- Support expiration across restarts.
- Reconcile database state with firewall state.
- Use least-privilege firewall management where practical.
- Do not let AI or the frontend execute arbitrary firewall commands.

## Important safety rule

During implementation, keep real firewall enforcement disabled until the executor is tested and explicitly approved for live use.

Do not run live block tests without asking me first.

Before any real firewall test, explain:

- Exact device being targeted
- Expected behavior
- Commands or rules to be applied
- Rollback method
- How SSH, DHCP, NAT, and unrelated clients remain protected

**Acceptance test:** With explicit approval, block one enrolled test device, verify its intended connectivity is restricted, then reverse the block while other clients remain online.

---

# 9. Phase G — Dashboard & User Experience

Complete the existing React dashboard rather than replacing it.

The administrator should be able to:

- Log in securely.
- See gateway status.
- See monitoring status.
- View connected devices.
- Inspect device details.
- View traffic history.
- View network topology.
- Review detection rules.
- Review incidents.
- Inspect incident evidence.
- View correlated incident history.
- View risk classifications.
- Propose security responses.
- Approve or reject actions.
- View active blocks.
- Reverse permitted actions.
- View audit logs.
- See system errors and degraded-service warnings.

Ensure that all UI controls connect to real backend behavior.

Remove or clearly label placeholder features.

Use accurate health indicators.

Do not display a system as healthy when packet capture, DHCP, database, or monitoring services have failed.

Preserve the existing frontend design wherever practical.

**Acceptance test:** The administrator can complete the entire non-AI workflow through the browser without using SSH for ordinary operations.

---

# 10. Phase H — Raspberry Pi Deployment

Create a repeatable, secure deployment process.

Target:

- Raspberry Pi 4 Model B
- 4 GB RAM
- Debian 13 ARM64
- Existing working gateway configuration

Requirements:

- Install compatible Python dependencies.
- Create an isolated Python environment.
- Configure environment variables securely.
- Provision SQLite storage.
- Apply Alembic migrations.
- Configure stable authentication secrets.
- Protect initial administrator setup.
- Configure secure dashboard/API serving.
- Implement appropriate capture permissions.
- Minimize root privileges.
- Create systemd services.
- Configure automatic startup.
- Support graceful shutdown.
- Support restart recovery.
- Add health checks.
- Add log rotation or retention.
- Document database backup and restore.
- Provide a safe update process.
- Provide rollback instructions.

Keep the Pi's existing network services operational.

Do not overwrite:

- NetworkManager configuration
- dnsmasq configuration
- Existing nftables gateway configuration
- SSH configuration
- Existing working routing/NAT rules

Deployment must preserve the ability to access the Pi remotely.

## SSH

The Pi is currently accessible from my laptop, typically through:

`ssh adam@inds-pi.local`

The SSH connection may already be open.

You may inspect the environment through SSH if available.

Do not assume SSH is connected until verified.

Before making system-level changes, show me the proposed commands and explain their effects.

Ask for approval before:

- Installing system packages
- Changing system services
- Changing firewall rules
- Altering permissions or privileged execution
- Restarting network-related services
- Rebooting the Pi

You may perform read-only inspection without asking.

**Acceptance test:** After approved deployment, the Pi boots and INDS starts independently without requiring my laptop.

---

# 11. Phase I — Testing & Validation

Implement comprehensive automated tests for all new functionality.

Include:

- Unit tests
- Backend integration tests
- Database migration tests
- Discovery tests
- Identity reconciliation tests
- Traffic attribution tests
- Detection tests
- Incident correlation tests
- Risk policy tests
- Response proposal tests
- Firewall executor tests using mocks
- Block expiration and reversal tests
- Authentication tests
- Frontend build and lint checks
- Browser end-to-end tests where practical
- ARM64 compatibility verification
- Raspberry Pi smoke tests

Use mocks for destructive firewall operations.

Do not use real network disruption as a substitute for unit tests.

Create a controlled acceptance-test checklist for:

1. Device connects.
2. Device receives DHCP lease.
3. Device appears in inventory.
4. Device traffic is recorded.
5. Detection rule triggers.
6. Incident is created.
7. Related incidents are correlated.
8. Deterministic risk is assigned.
9. Response is proposed.
10. Administrator approves.
11. Authorized block is applied.
12. Firewall state is verified.
13. Action is audited.
14. Block expires or is reversed.
15. Device connectivity is restored.
16. Dashboard displays the complete history.
17. Restart recovery works.

Do not claim tests passed unless they were actually executed.

---

# 12. AI — Explicitly Excluded

Do not integrate AI yet.

Do not:

- Add a DeepSeek API key.
- Make DeepSeek API requests.
- Install Ollama.
- Install Jev.
- Download AI models.
- Build AI prompts.
- Trigger AI assessments.
- Allow AI to execute firewall actions.

However, preserve a clean future integration boundary.

A future AI assessment should be able to provide:

- Classification
- Confidence estimate
- Suggested severity
- Supporting evidence references
- Alternative explanations
- Recommended response
- Model metadata

The policy engine must validate these fields independently.

AI failure must never interrupt deterministic monitoring or incident handling.

---

# 13. Execution Strategy

Work incrementally.

**Do not attempt to deploy everything in one unverified operation.**

Use this sequence:

1. Inspect current repository and Pi state.
2. Create a concise implementation plan.
3. Fix routed discovery and identity.
4. Complete traffic monitoring.
5. Complete deterministic detection and incidents.
6. Implement correlation and risk policy.
7. Complete response proposals and routed enforcement.
8. Complete dashboard integration.
9. Prepare production deployment.
10. Deploy to Pi after approval.
11. Perform controlled acceptance tests.
12. Document final status.

For local repository work, proceed through the implementation phases autonomously where safe.

Run tests after each significant change.

Do not stop after implementing one feature if more safe repository work remains.

However, pause and ask for approval before system-level Pi changes, privileged operations, or live firewall enforcement.

Do not bypass approval requirements to finish faster.

---

# 14. Required Final Deliverables

Produce:

**A. Completed codebase**

All non-AI functionality implemented and integrated, with tests.

**B. Deployment documentation**

Exact setup, startup, update, recovery, and rollback instructions.

**C. Architecture documentation**

Actual system architecture, data flow, service boundaries, and firewall design.

**D. Test report**

Executed tests, results, coverage, and limitations.

**E. Acceptance-test report**

Which end-to-end steps were verified on the actual Pi and which remain unverified.

**F. Remaining-work report**

Clearly distinguish:

- Completed
- Implemented but unverified
- Blocked pending approval
- Deferred
- AI integration remaining

**G. ChatGPT handoff summary**

Finish with a section titled:

"INDS Implementation Status — Handoff to ChatGPT"

Include:

- Files changed
- New services and components
- Database changes
- Deployment status
- Actual Pi verification results
- Commands executed
- Tests passed/failed
- Remaining blockers
- Exact next steps

The handoff must be self-contained so I can share it with ChatGPT.

---

# FINAL INSTRUCTIONS

This is an existing, functioning software project with a working hardware gateway.

Preserve what already works.

Do not redesign the entire repository unnecessarily.

Do not change our routed Pi topology.

Do not expose secrets.

Do not silently execute privileged operations.

Do not claim that a feature is complete based only on mocks.

Do not confuse laptop tests with real Raspberry Pi verification.

Do not integrate AI yet.

**Our final objective is a fully functional, independently operating INDS cybersecurity gateway, with every non-AI feature implemented, tested, and deployed.**

Start by inspecting the repository and checking the Pi's current state, then provide the implementation plan and proceed with safe local development.