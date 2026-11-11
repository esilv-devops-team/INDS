# Internal ON/OFF control — INDS-38

## Current scope

We are deferring the software ON/OFF switch until we build the internal dashboard
and monitoring services. It will be a software control for development and testing,
not a physical button or a customer-facing feature.

On 10 November 2026, we tested forwarding through the Pi without the INDS
application installed. Phone internet access worked before and after reboot, and
both Ethernet bridge ports started automatically. This confirms the forwarding
foundation; it does not test stopping or crashing monitoring services.

The gateway setup and hardware results are recorded on the INDS-36 branch.
Performance measurements and longer stability tests are still pending.

## How the switch will work

The internal dashboard will send ON/OFF requests to the backend running on the Pi.
The backend stays available in both modes so it can receive the next command.

| Mode | Behavior |
| --- | --- |
| ON | Start discovery, monitoring, detection, incident creation, and AI analysis. Blocking still requires administrator approval. |
| OFF | Stop security processing and new responses, remove INDS-managed restrictions, and preserve saved data. |
| Both | Keep Linux network forwarding running independently of the application. |

Switching OFF must also cancel queued work and ignore late AI results, so old
work cannot create incidents or apply blocks afterward. It must leave unrelated
firewall rules alone and report any failure to remove an INDS-managed block.
Switching ON again must not automatically restore old blocks without new approval.

After a restart, security processing starts OFF and the backend reconciles
unfinished work and stale rules. Automatically clearing blocks after a service
crash needs a separate decision; a crash must not stop network forwarding.

## Follow-up work

When the internal system is built:

- Implement the backend ON/OFF controller and connect it to the developer interface.
- Connect the controller to discovery, monitoring, detection, AI, and response services.
- Test OFF with pending work and active blocks, including cleanup failures.
- Verify saved history remains available and services cannot apply stale actions.
- Test forwarding while monitoring is stopped or crashes.

Keep the switch implementation as deferred work in Jira. Only the independent
forwarding part has been tested so far; the full ON/OFF behavior is not complete.
