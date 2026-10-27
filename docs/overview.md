# INDS overview

INDS protects one Wi-Fi network using a Raspberry Pi 4B (4 GB) as its gateway.
It will discover devices, monitor activity, detect threats, assist incident
analysis with DeepSeek, and apply authorized security responses.

## Network architecture

```text
Internet → Existing router → Ethernet → Raspberry Pi 4B
                                           │
                                  Protected Wi-Fi: INDS-Secure
                                           │
                                   Connected devices
```

Devices join the Pi's Wi-Fi so their routed traffic passes through INDS.
HTTPS contents remain encrypted. Direct traffic between Wi-Fi clients may
require separate AP controls. See [the workflow](workflow.md) for operation.

## Components

| Component | Responsibility |
| --- | --- |
| Gateway | Wi-Fi/routing, discovery observations, traffic collection, action execution |
| FastAPI backend | Coordination, inventory, incidents, authorization, database access |
| Local detection | Analyze observations and return findings |
| DeepSeek | Cloud-based analysis and response recommendations |
| React dashboard | Administrator views and controls through the backend API |
| SQLite | Local persistence using SQLAlchemy and Alembic |

## Repository

| Location | Contents |
| --- | --- |
| `backend/api/` | HTTP endpoints |
| `backend/services/` | Application logic |
| `backend/database/` | Configuration, models, sessions, migrations, generated SQL |
| `detection/rules/` | Detection algorithms, independent of persistence |
| `frontend/src/`, `frontend/public/` | React application and assets |
| `tests/unit/`, `tests/integration/` | Logic, API, persistence, and migration tests |
| `docs/` | Overview, database guide, operational workflow |
| `.github/workflows/` | CI checks |

Create `gateway/`, `ai/deepseek/`, and other directories when implementation
needs them. Keep runtime files, caches, dependencies, and build output out of Git.
Local data lives in `data/`; Python regenerates `__pycache__` automatically.

## Implementation status

**Implemented:** health and vendor lookup endpoints, MAC normalization,
randomized-MAC detection, severity classification, port scan rule, device/incident
models plus the complete approved relational schema, migrations, tests, and React starter.

**Planned:** gateway setup, discovery, continuous monitoring, DeepSeek integration,
incident workflow, response enforcement, and dashboard controls.

The target is one Pi and one protected network; no networks table is needed.
