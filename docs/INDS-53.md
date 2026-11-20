# INDS-53 — Review and reverse a block

In **Responses**, expand an approved block and select **Reverse block**.
After confirmation, the gateway removes the address from the managed set and
verifies it is absent. The original decision, execution history, and reversal
remain in SQLite. A failed verification leaves the action visible as
**Execution unknown**, with a retry available.

Monitoring OFF and backend restart reconcile the INDS block set. Failed
cleanup appears on the monitoring panel and can be retried from there.
Clear all blocks before disabling `INDS_FIREWALL_ENABLED`.

API and gateway command tests cover apply, reverse, retries, and protected
targets. Live Pi verification is pending.
