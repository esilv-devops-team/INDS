from fastapi import FastAPI

app = FastAPI(
    title="INDS API",
    description="Intelligent Network Detection & Response",
    version="0.1.0",
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "inds-backend"}
