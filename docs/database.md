# Database

SQLite runs locally inside the backend process. SQLAlchemy defines models and
sessions; Alembic is the only schema initialization and migration mechanism.

## Source and runtime data

```text
backend/database/
├── config.py        # INDS_DATABASE_URL and path resolution
├── base.py          # Shared metadata and UTC convention
├── session.py       # Lazy engine and sessions
├── models/          # Eight application entities
├── migrations/      # Alembic environment, template, and revisions
├── alembic.ini      # Single migration configuration
└── schema.sql       # Generated SQL reference
```

| Environment | Location |
| --- | --- |
| Development | `data/inds.sqlite3` |
| Tests | Isolated temporary files |
| Raspberry Pi | `/var/lib/inds/inds.sqlite3` |

The default `INDS_DATABASE_URL` is `sqlite:///data/inds.sqlite3`. Relative paths
resolve against the repository root. Set the environment before first database
use; restart after changing it. Database, WAL/SHM, and journal files are ignored.

## Initialize and migrate

From the repository root with the Python environment active:

```sh
python -m alembic -c backend/database/alembic.ini upgrade head
python -m alembic -c backend/database/alembic.ini current
python -m alembic -c backend/database/alembic.ini check
```

FastAPI startup never creates or changes the schema. For a schema change, edit
the model, generate a migration, review it, then upgrade and test:

```sh
python -m alembic -c backend/database/alembic.ini revision --autogenerate -m "describe change"
# Review constraints and data preservation before applying.
python -m alembic -c backend/database/alembic.ini upgrade head
python -m alembic -c backend/database/alembic.ini check
python -m pytest
```

Back up production before upgrading. Do not use `create_all()` or edit schema
through a GUI. Downgrading to `0001` removes the six new tables and their data;
downgrading to `base` destroys all application tables.

For the Pi, provision a directory owned by the service account (example `inds`),
then run migrations as that account with its project environment active:

```sh
sudo install -d -o inds -g inds -m 0700 /var/lib/inds
umask 077
export INDS_DATABASE_URL=sqlite:////var/lib/inds/inds.sqlite3
python -m alembic -c backend/database/alembic.ini upgrade head
```

Use the same URL in the backend service environment. Production dependencies
are installed from `backend/requirements.txt`; gateway deployment is still planned.
On PowerShell, use `$env:INDS_DATABASE_URL = 'sqlite:///C:/path/to/inds.sqlite3'`
to override the local file path.

## Security boundary

New data directories are private (`0700`) on POSIX; existing permissions are
not changed automatically. Use a dedicated unprivileged service account, a
`0077` service umask, and protect the database, WAL files, and backups. On Windows,
restrict access through directory ACLs. Standard SQLite does not encrypt these
files or provide per-administrator database access control.

No accounts or default credentials are seeded. `password_hash` stores only an
encoded salted password hash, never plaintext. Hashing/verification will belong
to the authentication service; use a maintained password-hashing library and
[Argon2id guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
The column constraint only rejects empty values; it cannot prove that a value
is a secure hash. Future API schemas must explicitly exclude credential fields.

SQLAlchemy hides bound parameters in SQL logs and exception strings. This does
not redact result-row debug logs or application logging: never log credentials,
API keys, or sensitive network evidence. Audit records are not a substitute for
authentication, authorization, or tamper-resistant external logging.

## Schema and sessions

| Table | Data |
| --- | --- |
| `administrators` | Unique normalized username, password hash, active flag, creation/login times |
| `devices` | Unique normalized MAC, current IP, hostname, vendor, trust flag, first/last seen |
| `monitoring_runs` | Start/stop times, administrator references, stop reason; only one unfinished run |
| `incidents` | Optional source device/run, rule, IP snapshots, observation times, optional score/severity, status, evidence, lifecycle times |
| `traffic_summaries` | Device/run, collection window, nonnegative byte/packet/connection counters |
| `ai_analyses` | Incident, model/prompt version, sanitized input, assessment, attempt status/times/error |
| `response_actions` | Incident/device/analysis references, target snapshots, idempotency key, approval and execution states, rate limit, lifecycle times/error |
| `audit_events` | Administrator/system actor, event/outcome, optional entity references, timestamp, details |
| `alembic_version` | Applied migration revision |

One device has many incidents. Deleting it clears the foreign key and preserves
incident history. Randomized MACs remain separate observed identities.
Constraints enforce valid MAC format, score range 0–100, defined severity/status
values, chronological timestamps, and a resolution time for resolved incidents.
Indexes cover device last-seen and incident status/time and source-device/time.
See [schema.sql](../backend/database/schema.sql) for exact fields and constraints.

Revision `0002` extends `0001` without replacing its device/incident records.
Legacy incidents have no monitoring run. Foreign-key enforcement stays ON
during migration; the incident rebuild uses a frozen revision snapshot so online
migrations and offline SQL follow the same history. Invalid non-object legacy
evidence causes a transactional failure rather than silent data conversion.

Administrator references use RESTRICT; deactivate identities instead of deleting
them. Traffic history restricts device deletion until purged. Incidents/actions
retain snapshots when their device is deleted. Analysis/response history restricts
incident deletion; purge dependents explicitly. Audit entity references become
NULL on deletion while event details survive. Audit records are intended to be
append-only through future services, not tamper-proof storage.

One unfinished monitoring run is enforced by a unique partial expression index.
SQLAlchemy cannot reflect this index for Alembic's drift comparison; integration
tests verify its enforcement directly. The related reflection warnings are expected.

## Approved operating rules

- Explicit human approval initially; local administrator accounts, no role/policy tables.
- AI results are advisory and never overwrite incident scores automatically.
- Monitoring starts OFF after restart; future coordination must reconcile interrupted runs.
- OFF preserves connectivity and existing restrictions until expiry or explicit removal.
- Expiry/removal must run independently of monitoring. An uncertain executor result is `unknown`, not automatically retried.
- Rate limits are in kilobits/second, applied separately to upload and download.
- Target 60-second traffic windows with seven-day retention; retain incident/AI/audit history for 90 days, except records needed by active actions.

These are design defaults, not implemented runtime jobs. Authentication, retention,
collection, restart reconciliation, approval endpoints, and command execution are
outside this database change. No accounts are seeded. Cross-record checks (an AI
analysis belongs to the response's incident, current target ownership, active
administrator authorization) belong in future service transactions.

All stored datetimes represent **UTC without timezone information**; normalize
external timestamps first. SQLAlchemy supplies timestamp/evidence defaults;
direct SQL inserts must supply required values. Replace evidence dictionaries
rather than mutating them in place.

Use one session per request/task, commit explicitly, and keep transactions short.
Uncommitted work rolls back on close. Do not share sessions or hold transactions
across network calls. Connections enable foreign keys, WAL, explicit transactions,
and a five-second busy timeout. SQLite permits one writer at a time.

## SQL reference and inspection

`schema.sql` is generated from migrations; never edit it independently or use it
instead of Alembic for initialization. Tests check it stays synchronized.
After adding a migration, regenerate it with this Python snippet from the root:

```python
from io import StringIO
from pathlib import Path
from alembic import command
from alembic.config import Config

sql = StringIO()
command.upgrade(Config("backend/database/alembic.ini", output_buffer=sql), "head", sql=True)
snapshot = "\n".join(line.rstrip() for line in sql.getvalue().rstrip().splitlines()) + "\n"
Path("backend/database/schema.sql").write_text(snapshot, encoding="utf-8")
```

This does not open a database. Future table-rebuild migrations must support
offline rendering to preserve snapshot generation.

In **DB Browser for SQLite**, open `data/inds.sqlite3` or a consistent Pi backup.
Use **Database Structure**, **Browse Data**, or **Execute SQL**:

```sql
SELECT version_num FROM alembic_version;
SELECT id, mac_address, last_seen_at FROM devices;
SELECT id, rule_code, status FROM incidents;
PRAGMA foreign_key_check;
```

Prefer read-only inspection. Keep live files on local storage. Use SQLite's
backup API for live backups, or stop all database users cleanly before copying;
copying only an active database file can omit WAL contents.
