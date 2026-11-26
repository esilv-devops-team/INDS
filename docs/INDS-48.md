# INDS-48 - DeepSeek incident analysis

Every new incident is analysed by DeepSeek in the background. Detection and
packet capture never wait for it, and they keep working when DeepSeek is down.

## Configuration

| Variable | Required | Default |
|---|---|---|
| `INDS_DEEPSEEK_API_KEY` | yes | none |
| `INDS_DEEPSEEK_MODEL` | no | `deepseek-flash` |

The key is only read by the backend. It is never sent to the dashboard, never
saved in the database and never written in the logs. Never put it in a file of
the repository.

- Mac (development): `export INDS_DEEPSEEK_API_KEY="..."` in the terminal
  before starting uvicorn.
- Raspberry Pi: add `INDS_DEEPSEEK_API_KEY=...` to `/etc/inds/inds.env`.

Without a key every analysis ends as Failed with "DeepSeek API key not
configured." and the rest of INDS works normally.

## Flow

1. When a new incident is created, `queue_analysis` adds a `pending` row in
   `ai_analyses`. Repeated findings on the same incident do not add another
   one: there is only one active analysis per incident.
2. `AnalysisWorker` (started with the API) checks every 2 seconds for a pending
   analysis, marks it `running`, builds the context (INDS-83) and calls
   DeepSeek (`backend/services/deepseek.py`).
3. The answer is validated and saved as `succeeded` with the audit event
   `ai_analysis.attached`, or the attempt is saved as `failed` with the reason
   and the audit event `ai_analysis.failed`.

Dashboard names: pending = Pending, running = Analyzing, succeeded = Completed,
failed = Failed.

## DeepSeek answer

DeepSeek is called with JSON output and must answer with:

`summary`, `classification`, `explanation`, `risk_level` (Low, Medium, High,
Critical), `evidence` (list), `impact`, `recommended_action`, `justification`,
`confidence` (0 to 100) and `uncertainty`.

Any missing or invalid field makes the attempt fail. Texts are trimmed and
limited to 1500 characters, the evidence list to 10 items. The risk level is
only advice: it never changes the severity or the risk score of the incident.

## Failures and retries

| Problem | Retry |
|---|---|
| timeout (30 s), network error, HTTP 429/5xx, invalid JSON or answer | yes |
| missing key, HTTP 401/402/403, unexpected error | no |

An analysis is tried at most 3 times: the second try 30 seconds after the
first failure and the third 2 minutes after the second. Each try is its own
row in `ai_analyses`.

## Monitoring OFF and restarts

- When the monitoring run of the incident has ended (OFF, shutdown, failure),
  waiting analyses are cancelled and a result that arrives late is discarded
  (`cancelled`).
- When INDS restarts, analyses left `running` go back to `pending`. The old
  monitoring run is closed as interrupted at startup, so the worker then marks
  them `cancelled`. No row stays stuck as running.

## Tests

`tests/unit/test_deepseek.py` mocks the HTTP call (success, timeout, network
error, HTTP errors, invalid JSON and invalid answers).
`tests/integration/test_ai_analysis.py` covers the queue, duplicates, retries,
monitoring OFF, late results, restarts and the background worker. No test uses
a real key or the internet.
