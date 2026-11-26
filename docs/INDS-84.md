# INDS-84 - AI analysis in the incident dashboard

The incident panel has an "AI analysis" section that shows the latest DeepSeek
analysis of the incident (`frontend/src/components/AIAnalysis.jsx`). The panel
already refreshes every 5 seconds, so the section follows the analysis until it
is finished.

## Status

| Database | Dashboard |
|---|---|
| `pending` | Pending (or "next try at ..." after a failed try) |
| `running` | Analyzing |
| `succeeded` | Completed |
| `failed` | Failed, with the reason and a "Try again" button |
| `cancelled` | Cancelled because the monitoring was stopped |

When an incident has no analysis yet (for example an incident from before
INDS-48), the section shows an "Analyse with AI" button.

## Completed analysis

Summary, AI risk level, classification, confidence, what is happening, the
evidence list, the possible impact, the recommended action with its
justification and the note of INDS-51 (proposed or why not), and the
uncertainty. The AI risk level is labelled as the AI's opinion: the severity
and the score of INDS do not change.

When the analysis created a block proposal, it is shown inside the section with
its approval and gateway state and the same Approve / Reject buttons as in the
"Proposed responses" list. Both use `POST /api/actions/{id}/decision`.

## API changes

- `GET /api/incidents/{id}`: analyses now include `started_at`, actions include
  `ai_analysis_id` (to find the proposal of an analysis).
- `POST /api/incidents/{id}/analysis` (administrator): queues a new analysis.
  Returns 202, or 409 when an analysis is already pending or running, when the
  incident already has a completed analysis, or when the monitoring run of the
  incident was stopped. Audit event `ai_analysis.requested`.

## History

New lines in the incident history: "AI analysis completed by <model> (risk
<level>)", "AI analysis failed: <reason>" and "New AI analysis requested".

Analyses are stored in `ai_analyses`, so everything is still shown after
restarting INDS.

## Tests

`tests/integration/test_ai_analysis_api.py`: login required, first analysis,
duplicate request, retry after a failure, refused requests (completed, stopped
run, unknown incident) and the link between the analysis and its proposal.
