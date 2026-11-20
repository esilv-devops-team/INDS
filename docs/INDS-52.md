# INDS-52 — Approve and apply a device block

Install the [gateway policy](INDS-37.md) first. On the Pi backend, set
`INDS_FIREWALL_ENABLED=1`, set `INDS_MONITOR_INTERFACE` to the policy's
AP-facing port, and set `INDS_MONITOR_AP_MAC` to the access point's MAC.
Use one backend process with permission to update nftables.

While monitoring is ON, an administrator approves a pending block on the
incident page. The target must be an untrusted inventory device learned on
the guest port. INDS records the decision and checks the kernel block set
before reporting the block as active. An unconfirmed operation appears as
**Execution unknown**.

This flow handles untimed block proposals already in SQLite. Pi acceptance
requires verifying that a test guest loses connectivity while other guests
remain connected, then restoring the test guest through [INDS-53](INDS-53.md).
