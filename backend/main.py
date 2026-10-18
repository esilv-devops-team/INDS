from fastapi import FastAPI

from backend.api.devices import router as devices_router

app = FastAPI(
    title="INDS API",
    description="Intelligent Network Detection & Response",
    version="0.1.0",
)

app.include_router(devices_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "inds-backend"}
