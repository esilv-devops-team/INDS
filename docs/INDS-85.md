# INDS-85 - AI workflow on the Raspberry Pi

End to end check of the AI part on the real Pi with real traffic: detection,
incident, DeepSeek analysis, block proposal, approval, block on the gateway and
reversal. Nothing is simulated: no mocked AI, no seeded incidents.

Run it after the Live Network work is merged and the latest `main` is deployed
with [the routed deployment plan](gateway/routed-deployment.md).

## 1. Before the test

- `main` is green in GitHub Actions (tests, coverage, lint, build).
- The release on the Pi was installed with
  `pip install -r backend/requirements.txt -r gateway/requirements.txt`
  (the AI needs `httpx`) and the database is migrated (`alembic upgrade head`).
- `/etc/inds/inds.env` (root only, `chmod 0600`) contains the usual settings and:

```sh
INDS_DEEPSEEK_API_KEY=<key>
INDS_DEEPSEEK_MODEL=deepseek-flash
INDS_ALLOW_BLOCK_PROPOSALS=1
INDS_FIREWALL_ENABLED=1
```

  `INDS_FIREWALL_ENABLED=1` needs the approved firewall socket and helper from
  the deployment plan. `INDS_MONITOR_AP_MAC` and `INDS_PROTECTED_MACS` must list
  the AP, the Pi management client and every device that must never be blocked.
- The Pi reaches DeepSeek (the key stays out of the shell history):

```sh
sudo bash -c 'set -a; . /etc/inds/inds.env; curl -s -o /dev/null -w "%{http_code}\n" https://api.deepseek.com/models -H "Authorization: Bearer $INDS_DEEPSEEK_API_KEY"'
```

  `200` means the key works. `401` is a wrong key, `402` an empty balance.
- Port scans are High for the demo, so they can get a block proposal right
  away (configuration only, applies when monitoring starts):

```sh
cd /opt/inds/current
sudo -u inds env INDS_DATABASE_URL=sqlite:////var/lib/inds/inds.sqlite3 .venv/bin/python -m backend.manage_rules set PORT_SCAN severity=High
```

- Restart with `sudo systemctl restart inds` and check
  `curl --fail http://127.0.0.1:8000/health`.
- The test laptop (the "attacker") is an authorized device of the team,
  connected to the INDS AP, with a DHCP lease from the Pi, not trusted and not
  in `INDS_PROTECTED_MACS`.

## 2. Test cases

Open the dashboard through the SSH tunnel and turn monitoring ON.

| # | Step | Expected result |
|---|---|---|
| 1 | From the test laptop, check internet access (`curl -I https://example.com`) | works |
| 2 | From the test laptop, scan the Pi: `sudo nmap -sS -p 1-200 192.168.50.1` | a High `PORT_SCAN` incident appears within a few seconds with the laptop as source |
| 3 | Open the incident, AI analysis section | Pending then Analyzing then Completed in less than 30 s, all fields filled |
| 4 | Read the recommendation | `Block the device` with a justification, note "Block proposed, waiting for the administrator.", proposal shown in the section |
| 5 | Check the severity and score of the incident | unchanged by the AI risk level |
| 6 | Click Approve, then Yes | approval Approved, gateway state Active |
| 7 | From the test laptop, check internet access again | blocked, while the Pi, SSH and the other phone still work |
| 8 | Responses page, reverse the block | gateway state Removed |
| 9 | From the test laptop, check internet access | works again |
| 10 | Incident history | Detected as High, AI analysis completed, Response proposed, Response approved, Block applied, Removal requested, Block removed |
| 11 | Mark the first incident as resolved. Unplug the Pi upstream cable (`eth0`), wait for the 5 min rule cooldown, scan again (`sudo nmap -sS -p 300-500 192.168.50.1`) | a new incident is still created, its analysis ends Failed ("Could not reach the DeepSeek API.") and is tried again after 30 s and 2 min |
| 12 | Plug `eth0` back, click Try again on that incident | Completed |
| 13 | `sudo systemctl restart inds`, reload the dashboard | analyses and responses are still there |
| 14 | Turn monitoring OFF while an analysis is pending | it ends Cancelled, no late result is saved |

A second scenario for the presentation is ARP spoofing (already High by
default) from the same laptop against a protected address.

## 3. No fake data

Before the presentation, check the production database on the Pi only has
real records:

```sh
cd /opt/inds/current
sudo -u inds env INDS_DATABASE_URL=sqlite:////var/lib/inds/inds.sqlite3 .venv/bin/python -c "
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from backend.database.models import AIAnalysis, Incident
from backend.database.session import get_engine
with Session(get_engine()) as s:
    print('incidents', s.scalar(select(func.count(Incident.id))), 'without run', s.scalar(select(func.count(Incident.id)).where(Incident.monitoring_run_id.is_(None))))
    print('analyses by model', s.execute(select(AIAnalysis.model, func.count()).group_by(AIAnalysis.model)).all())
"
```

Every incident must belong to a monitoring run and every analysis must use the
DeepSeek model. Test databases from development machines are never copied to
the Pi.

## 4. Results

| # | Date | Result | Notes |
|---|---|---|---|
| 1-14 | | | |

## 5. Rollback

Reverse active blocks from the dashboard first. Set `INDS_FIREWALL_ENABLED=0`
and restart to go back to monitor-only. Without `INDS_DEEPSEEK_API_KEY` INDS keeps
detecting and every analysis ends Failed with "DeepSeek API key not
configured.".
