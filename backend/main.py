from fastapi import FastAPI

from backend.api.auth import router as auth_router
from backend.api.devices import router as devices_router
from backend.api.errors import add_error_handlers
from backend.api.gateway import router as gateway_router
from backend.api.incidents import router as incidents_router
from backend.api.system import router as system_router

app = FastAPI(
    title="INDS API",
    description="Intelligent Network Detection & Response",
    version="0.1.0",
)

add_error_handlers(app)

app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(incidents_router)
app.include_router(system_router)
app.include_router(gateway_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "inds-backend"}