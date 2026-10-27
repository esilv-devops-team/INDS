# INDS — Intelligent Network Detection & Response

A Raspberry Pi 4B network security project: local threat detection, a React
dashboard, DeepSeek-assisted analysis, and authorized gateway responses.

**Team:** Adam Hawash and Firas El Kheshen.

## Documentation

- [Overview](docs/overview.md) — architecture, repository structure, and current status.
- [Database](docs/database.md) — storage, initialization, migrations, and inspection.
- [Workflow](docs/workflow.md) — discovery, monitoring, detection, analysis, response, and OFF behavior.

## Development

Use Python 3.12+ and Node.js 22. From the repository root:

```sh
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or
`.\.venv\Scripts\Activate.ps1` in PowerShell, then:

```sh
python -m pip install -r backend/requirements-dev.txt
python -m alembic -c backend/database/alembic.ini upgrade head
python -m uvicorn backend.main:app --reload
```

API: `http://127.0.0.1:8000`; API docs: `http://127.0.0.1:8000/docs`.
In a separate terminal:

```sh
cd frontend
npm ci
npm run dev
```

## Checks

From the root with the Python environment active:

```sh
python -m pytest
python -m alembic -c backend/database/alembic.ini check
python -m pip check
```

From `frontend/`:

```sh
npm run lint
npm run build
```

CI runs Python tests and frontend lint/build. Work from a Jira story, use a branch
containing its issue key, and request teammate review before merging to `main`.
