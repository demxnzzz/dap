from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..extractors import extract_routes
from ..github_sync import upsert_assets
from ..models import Asset, Repository
from ..serializers import asset_out

router = APIRouter(prefix="/api", tags=["assets"])


class SourceFile(BaseModel):
    path: str
    content: str


class ScanIn(BaseModel):
    files: list[SourceFile]


@router.get("/assets")
def list_assets(
    repository_id: int | None = None,
    method: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Asset).order_by(Asset.path.asc())
    if repository_id:
        query = query.filter(Asset.repository_id == repository_id)
    if method:
        query = query.filter(Asset.method == method.upper())
    assets = query.limit(1000).all()
    names = {repo.id: repo.name for repo in db.query(Repository).all()}
    return [asset_out(asset, names.get(asset.repository_id)) for asset in assets]


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    db.commit()
    return None


@router.post("/repositories/{repo_id}/scan-files")
def scan_files(repo_id: int, payload: ScanIn, db: Session = Depends(get_db)):
    repository = db.get(Repository, repo_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    if not payload.files:
        raise HTTPException(422, "Attach at least one source file to scan")
    if len(payload.files) > 200:
        raise HTTPException(422, "Scan at most 200 files at a time")

    routes: list[dict] = []
    files_scanned = 0
    for file in payload.files:
        if not (file.path or "").strip():
            continue
        routes.extend(extract_routes(file.path, file.content or ""))
        files_scanned += 1

    added, updated = upsert_assets(db, repository, routes)
    db.commit()
    return {
        "files_scanned": files_scanned,
        "routes_found": len(routes),
        "assets_added": added,
        "assets_updated": updated,
    }
