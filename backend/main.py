from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import inspect
from starlette.concurrency import run_in_threadpool

from backend.api.actions import router as actions_router
from backend.api.auth import router as auth_router
from backend.api.devices import router as devices_router
from backend.api.errors import add_error_handlers
from backend.api.gateway import router as gateway_router
from backend.api.incidents import router as incidents_router
from backend.api.rules import router as rules_router
from backend.api.statistics import router as statistics_router
from backend.api.system import router as system_router
from backend.database.config import get_database_url
from backend.database.session import get_engine
from backend.services.monitoring import MonitoringController, MonitoringError, close_run


@asynccontextmanager
async def lifespan(app):
    def reconcile():
        path = Path(get_database_url().database)
        if path.is_file():
            engine = get_engine()
            if inspect(engine).has_table("monitoring_runs"):
                close_run(engine, "interrupted")
                try:
                    app.state.monitoring.cleanup_firewall(engine)
                except MonitoringError:
                    # Keep the dashboard available so administrators can inspect and retry cleanup.
                    pass

    await run_in_threadpool(reconcile)
    try:
        yield
    finally:
        await run_in_threadpool(app.state.monitoring.shutdown)

app = FastAPI(
    title="INDS API",
    description="Intelligent Network Detection & Response",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.monitoring = MonitoringController()

add_error_handlers(app)

app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(incidents_router)
app.include_router(system_router)
app.include_router(gateway_router)
app.include_router(actions_router)
app.include_router(statistics_router)
app.include_router(rules_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "inds-backend"}
