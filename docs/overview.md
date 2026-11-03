# INDS overview

INDS protects one Wi-Fi network using a Raspberry Pi 4B (4 GB) as its gateway.
It will discover devices, monitor activity, detect threats, assist incident
analysis with DeepSeek, and apply authorized security responses.

## Network architecture

```text
Customers <-> Guest Wi-Fi AP <-> Raspberry Pi inline bridge <-> Router <-> Internet
                                built-in Ethernet + USB Ethernet
```

The separate AP provides Wi-Fi. The Pi transparently bridges its two wired ports;
the existing router remains responsible for DHCP and routing to the internet.
The AP must have no uplink that bypasses the Pi. HTTPS contents remain encrypted.
Traffic between clients on the same AP may not cross the Pi.
See [gateway setup](gateway/setup.md) and [the workflow](workflow.md).

## Components

| Component | Responsibility |
| --- | --- |
| Gateway | Independent Ethernet bridging, discovery observations, traffic collection, approved action execution |
| FastAPI backend | Coordination, inventory, incidents, authorization, database access |
| Local detection | Analyze observations and return findings |
| DeepSeek | Cloud-based analysis and response recommendations |
| React dashboard | Administrator views and controls through the backend API |
| SQLite | Local persistence using SQLAlchemy and Alembic |

## Repository

| Location | Contents |
| --- | --- |
| `gateway/config/`, `gateway/scripts/` | Host network templates and inspection helpers |
| `backend/api/` | HTTP endpoints |
| `backend/services/` | Application logic |
| `backend/database/` | Configuration, models, sessions, migrations, generated SQL |
| `detection/rules/` | Detection algorithms, independent of persistence |
| `frontend/src/`, `frontend/public/` | React application and assets |
| `tests/unit/`, `tests/integration/` | Logic, API, persistence, and migration tests |
| `docs/` | Overview, database guide, operational workflow |
| `.github/workflows/` | CI checks |

Create `ai/deepseek/` and other directories only when implementation needs them. Keep runtime files, caches, dependencies, and build output out of Git.
Local data lives in `data/`; Python regenerates `__pycache__` automatically.

## Implementation status

**Implemented:** health and vendor lookup endpoints, MAC normalization,
randomized-MAC detection, severity classification, port scan rule, device/incident
models plus the complete approved relational schema, migrations, tests, and React starter.

**Prepared, not hardware-validated:** inline bridge template, setup/recovery guide,
and forwarding/performance verification checklist in `gateway/` and `docs/gateway/`.

**Planned:** deployed gateway, discovery, continuous monitoring, DeepSeek integration,
incident workflow, response enforcement, and dashboard controls.

The target is one Pi and one protected network; no networks table is needed.
