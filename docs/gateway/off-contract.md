# Internal ON/OFF contract (INDS-38)

Status: requirements and acceptance preparation only. No runtime controller,
collectors, AI worker, or firewall executor is implemented.

## Internal OFF contract: future integration checks

These require services not implemented yet; they are not completed by creating
the bridge. ON/OFF is an internal development control, not a café-owner feature.

- OFF prevents new observations, detections, AI submissions, and response execution.
- Cancel queued work and stop/discard in-flight AI results after OFF; an external
  request already sent cannot be recalled. Stale work cannot create new incidents
  or apply rules after the transition.
- Remove all INDS-managed restrictions, including future rate limits, while
  preserving unrelated firewall rules. Retain decisions and removal history.
- Report cleanup failures explicitly; do not claim successful OFF while an
  INDS-managed restriction remains. Prevent approval/execution races during cleanup.
- Preserve device inventory, incidents, analyses, summaries, and audit history.
- ON after OFF must not silently reapply old blocks; require a new approval.
- Start OFF after restart and reconcile interrupted work and stale managed rules.
- Forwarding remains independent of collectors, database, detection, and DeepSeek.

Existing kernel firewall rules can outlive a detection process. A detection crash
must not stop forwarding; whether it must also automatically clear approved blocks
needs a separate crash-cleanup policy. Explicit OFF always clears managed blocks.

AP-local device-to-device traffic may never cross the Pi. Record this visibility
limit instead of claiming complete monitoring of every guest interaction.

## Acceptance evidence still required

On the inline Pi, verify client DHCP, DNS, HTTPS, and continuous probes with the
INDS application absent, stopped, and (when implemented) deliberately crashed.
Record interruptions, packet loss, and forwarding recovery after a Pi reboot.
The reboot itself can interrupt connectivity; physical failover is out of scope.
Exercise OFF with an active approved block and pending work; verify rule removal,
history retention, race prevention, and explicit reporting of cleanup failures.
Keep INDS-38 open until its runtime behavior is implemented and tested.
