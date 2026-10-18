# INDS — Intelligent Network Detection & Response

INDS is a Raspberry Pi-based network security platform designed to monitor, detect, and respond to suspicious activity on a protected Wi-Fi network.

## Project Team

- Adam Hawash
- Firas El Kheshen

## Architecture

Internet
    |
Existing Router
    |
Ethernet
    |
Raspberry Pi (Wi-Fi Gateway)
    |
Protected Wi-Fi Clients

The Raspberry Pi acts as a network gateway, providing device discovery, traffic monitoring, threat detection, incident management, and administrative response capabilities.

## Technology Stack

- Hardware: Raspberry Pi 4 Model B (4 GB RAM)
- Backend: Python, FastAPI
- Frontend: React, Vite
- Database: SQLite (planned)
- Networking: Linux, Wi-Fi AP, nftables
- Detection: Python-based monitoring and detection rules
- AI: Optional DeepSeek API integration
- CI/CD: GitHub Actions
- Project Management: Jira Scrum

## Project Structure

- `backend/` — API, services, and data models
- `frontend/` — React dashboard
- `gateway/` — Network gateway and firewall
- `detection/` — Traffic monitoring and detection rules
- `ai/` — Optional AI integration
- `tests/` — Automated tests
- `docs/` — Requirements and architecture documentation
- `scripts/` — Development and deployment scripts

## Backend Development

Create and activate a Python virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r backend/requirements-dev.txt

Start the API:

    uvicorn backend.main:app --reload

Run tests:

    python -m pytest

## Frontend Development

    cd frontend
    npm ci
    npm run dev

Production build:

    npm run build

Lint:

    npm run lint

## Development Workflow

1. Select a Jira User Story.
2. Create a feature branch containing its Jira issue key.
3. Implement and test the changes.
4. Open a Pull Request targeting `main`.
5. Request review from the other team member.
6. Merge after successful CI checks and review.

## Project Status

Initial project setup. Backend health endpoint and React starter application are operational.

Network gateway, monitoring, detection, AI analysis, and response functionality are not yet implemented.
