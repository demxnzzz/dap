from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..cvss import evaluate
from ..db import get_db
from ..demo_data import load_demo
from ..models import Asset, CommitRecord, Finding, Report, Repository
from ..queries import repository_counts
from ..serializers import asset_out, commit_out, finding_out, repo_out

router = APIRouter(prefix="/api", tags=["workspace"])


class VectorIn(BaseModel):
    vector: str


@router.get("/stats")
def stats(repository_id: int | None = None, db: Session = Depends(get_db)):
    def count(model, *filters):
        return db.query(func.count(model.id)).filter(*filters).scalar() or 0

    repo_filter = [Finding.repository_id == repository_id] if repository_id else []
    asset_filter = [Asset.repository_id == repository_id] if repository_id else []
    commit_filter = [CommitRecord.repository_id == repository_id] if repository_id else []

    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(*repo_filter)
        .group_by(Finding.severity)
        .all()
    )
    status_rows = (
        db.query(Finding.status, func.count(Finding.id))
        .filter(*repo_filter)
        .group_by(Finding.status)
        .all()
    )
    framework_rows = (
        db.query(Asset.framework, func.count(Asset.id))
        .filter(*asset_filter)
        .group_by(Asset.framework)
        .order_by(func.count(Asset.id).desc())
        .all()
    )
    method_rows = (
        db.query(Asset.method, func.count(Asset.id))
        .filter(*asset_filter)
        .group_by(Asset.method)
        .all()
    )

    names = {repo.id: repo.name for repo in db.query(Repository).all()}
    recent_commits = (
        db.query(CommitRecord)
        .filter(*commit_filter)
        .order_by(CommitRecord.committed_at.desc())
        .limit(5)
        .all()
    )
    recent_findings = (
        db.query(Finding)
        .filter(*repo_filter)
        .order_by(Finding.created_at.desc())
        .limit(5)
        .all()
    )
    recent_assets = (
        db.query(Asset)
        .filter(*asset_filter)
        .order_by(Asset.last_seen.desc())
        .limit(6)
        .all()
    )

    return {
        "targets": count(Repository)
        if not repository_id
        else 1,
        "assets": count(Asset, *asset_filter),
        "commits": count(CommitRecord, *commit_filter),
        "flagged_commits": count(
            CommitRecord,
            *commit_filter,
            CommitRecord.risk_level.in_(["high", "medium"]),
        ),
        "findings": count(Finding, *repo_filter),
        "open_findings": count(
            Finding,
            *repo_filter,
            Finding.status.in_(["new", "triaged", "confirmed"]),
        ),
        "reports": count(Report, *repo_filter),
        "severity_counts": {row[0]: row[1] for row in severity_rows},
        "status_counts": {row[0]: row[1] for row in status_rows},
        "framework_counts": [
            {"framework": row[0] or "unknown", "count": row[1]} for row in framework_rows
        ],
        "method_counts": [
            {"method": row[0] or "GET", "count": row[1]} for row in method_rows
        ],
        "recent_commits": [
            commit_out(commit, names.get(commit.repository_id))
            for commit in recent_commits
        ],
        "recent_findings": [
            finding_out(finding, names.get(finding.repository_id))
            for finding in recent_findings
        ],
        "recent_assets": [
            asset_out(asset, names.get(asset.repository_id)) for asset in recent_assets
        ],
    }


@router.post("/cvss/evaluate")
def cvss_evaluate(payload: VectorIn):
    try:
        return evaluate(payload.vector)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.post("/demo/load")
def load_demo_workspace(db: Session = Depends(get_db)):
    repository, created = load_demo(db)
    return {
        "repository": repo_out(repository, repository_counts(db, repository.id)),
        "created": created,
    }
