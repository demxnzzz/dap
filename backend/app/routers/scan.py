from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..github_sync import github_token
from ..oneshot import ScanError, run_scan

router = APIRouter(prefix="/api", tags=["scan"])


class ScanIn(BaseModel):
    url: str
    researcher: str = ""
    platform: str = "HackerOne"
    max_reports: int = 8


@router.post("/scan", status_code=201)
def scan_repository(payload: ScanIn, db: Session = Depends(get_db)):
    url = (payload.url or "").strip()
    if not url:
        raise HTTPException(422, "Paste a GitHub or GitLab repository URL first.")
    try:
        return run_scan(
            db,
            url,
            researcher=(payload.researcher or "").strip()[:160],
            platform=(payload.platform or "HackerOne").strip()[:60],
            max_reports=payload.max_reports,
            token=github_token(),
        )
    except ScanError as exc:
        db.rollback()
        raise HTTPException(exc.status_code, exc.message)
