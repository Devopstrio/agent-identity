import uvicorn
from fastapi import FastAPI
from agent_identity.api.endpoints import router as identity_router
import structlog

logger = structlog.get_logger()

app = FastAPI(
    title="Agent Identity (SPIFFE CA)",
    description="Zero-Trust mTLS Certificate Authority for Autonomous AI Agents",
    version="1.0.0"
)

app.include_router(identity_router, prefix="/v1/identity", tags=["Workload Identity"])

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy"}

def start() -> None:
    logger.info("Starting Agent Identity CA on 0.0.0.0:8081")
    uvicorn.run("agent_identity.main:app", host="0.0.0.0", port=8081, reload=True)

if __name__ == "__main__":
    start()
