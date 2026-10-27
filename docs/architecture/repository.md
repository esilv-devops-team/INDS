# Repository organization

Keep code close to the subsystem that owns its responsibility. Create new
directories when implementation needs them. Keep only directories containing
implementation or documentation; do not add placeholders for future features.

| Location | Responsibility |
| --- | --- |
| `backend/main.py` | FastAPI application setup and router registration |
| `backend/api/` | HTTP routes, request handling, and response mapping |
| `backend/services/` | Application operations, including vendor lookup and incident severity classification |
| `detection/rules/` | Threat detection rules, currently port scan detection |
| `frontend/public/` | Static assets served directly |
| `frontend/src/` | React entry point, application, styles, and imported assets |
| `tests/unit/` | Isolated service and detection rule tests |
| `tests/integration/` | API tests that exercise the FastAPI application through TestClient |
| `docs/architecture/` | Architecture and repository organization |
| `.github/workflows/` | Continuous integration |

## Adding code

- Keep API handlers in `backend/api/` and application logic in
  `backend/services/`. Keep threat detection algorithms in `detection/rules/`.
- Keep traffic collection in `gateway/` and analysis of that traffic in
  `detection/`. Add gateway network, discovery, monitoring, firewall, and traffic
  control modules only when implemented. Keep gateway connectivity independent
  from the monitoring lifecycle.
- Keep workflow coordination, inventory, incidents, and response authorization
  in backend services. Gateway adapters execute authorized actions; DeepSeek
  integration belongs in `ai/deepseek/` and supplies analysis and recommendations.
- Add `backend/schemas/`, `backend/database/`, and `backend/core/` when request
  schemas, persistence, or shared configuration respectively need their own
  modules.
- Add `backend/models/` for persistent entities when needed. Keep requirements
  documents in `docs/requirements/`, operational guidance in `docs/operations/`,
  and development/deployment utilities in `scripts/` as those files are added.
- Keep the current React starter in `frontend/src/`. Add `components/`, `pages/`,
  `hooks/`, and `services/` as reusable UI, screens, hooks, and API clients appear.
- Preserve Python package initializers and use imports rooted at `backend` or
  `detection`. Run Python commands from the repository root.
- Keep dependencies with their applications: Python requirements in `backend/`
  and npm manifests in `frontend/`. Root-level `pytest.ini` configures both
  Python subsystems; CI runs the same checks described in the root README.

Do not check in virtual environments, node_modules, build output, or coverage
reports. Do not add `.gitkeep` files or empty Python packages for planned work.
