from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import Base, engine, wait_for_db
from .routers import assets, changes, findings, invariants, reports, scan, targets, workspace


@asynccontextmanager
async def lifespan(_app: FastAPI):
    wait_for_db()
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="DAP — Bug Hunting Workbench",
    version="0.1.0",
    description="Targets, commit diff review, attack-surface inventory, SARIF triage and report drafting.",
    lifespan=lifespan,
)

app.include_router(targets.router)
app.include_router(changes.router)
app.include_router(assets.router)
app.include_router(invariants.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(scan.router)
app.include_router(workspace.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
