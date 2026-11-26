# INDS-51 - AI-assisted response recommendations

When a DeepSeek analysis succeeds (INDS-48), its `recommended_action` is turned
into a response proposal by `propose_response` in
`backend/services/ai_recommendation.py`. The administrator approves or rejects
it with the normal response workflow. The AI never runs a command and never
touches the firewall itself.

## Supported actions

| AI answer | What INDS does |
|---|---|
| `block` | goes through the response policy, then a pending block may be proposed |
| `monitor` | nothing, INDS keeps monitoring |
| anything else | refused and saved as `monitor` |

## Checks before a block is proposed

1. The existing response policy (`assess_response`) must allow a block: the
   incident is High or Critical and not resolved, the device address is
   confirmed (DHCP lease or neighbor table), the device is not trusted or
   protected (`INDS_MONITOR_AP_MAC`, `INDS_PROTECTED_MACS`) and block proposals
   are enabled (`INDS_ALLOW_BLOCK_PROPOSALS`).
2. No block for the same device is already pending or active
   (`open_block_exists`, now shared with the manual proposal API).

## The proposal

- `response_actions` row: `action_type` block, `approval_status` pending,
  linked to the incident and to the AI analysis (`ai_analysis_id`), no
  requester (it comes from INDS), reason `AI: <justification>` (max 300
  characters).
- Critical incidents get a temporary block of 15 minutes, like a manual
  proposal.
- Audit event `response_action.proposed` with the system as actor.

The analysis keeps a `response_note` in its assessment that explains what
happened, for example "Block proposed, waiting for the administrator." or
"Block not proposed: Device is protected or protection settings are invalid."

## Approval

The proposal is approved or rejected with `POST /api/actions/{id}/decision`,
like every other response. Monitoring must be ON to approve, and the firewall
is only touched when `INDS_FIREWALL_ENABLED=1`.

The risk level given by the AI is only advice. It never changes the severity
or the risk score computed by INDS.

## Privacy fix

Since repeated findings keep a nested `latest_finding` in the incident
evidence, the INDS-83 context now cleans nested objects too, so no IP address,
MAC address or hostname inside them reaches DeepSeek.

## Tests

`tests/integration/test_ai_recommendation.py`: proposal created, temporary
block, monitor, unsupported action, policy refusals (low risk, trusted device,
unconfirmed address, resolved incident, proposals disabled), duplicate block,
approve and reject. `tests/integration/test_ai_context.py`: nested evidence.
