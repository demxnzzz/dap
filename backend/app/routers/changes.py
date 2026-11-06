from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import CommitRecord, DiffFile, Repository
from ..security import file_flags, risk_level
from ..serializers import commit_out

router = APIRouter(prefix="/api", tags=["changes"])


class DiffImportIn(BaseModel):
    message: str
    diff_text: str
    author: str = "manual import"
    filename: str = "changes.patch"
    sha: str | None = None


class ReviewIn(BaseModel):
    reviewed: bool = True


def parse_unified_diff(text: str, fallback_filename: str) -> list[dict]:
    text = (text or "").strip("\n")
    if not text.strip():
        raise ValueError("Diff is empty")

    if re.search(r"^diff --git ", text, re.MULTILINE):
        chunks = re.split(r"(?=^diff --git )", text, flags=re.MULTILINE)
    elif re.search(r"^--- ", text, re.MULTILINE):
        chunks = re.split(r"(?=^--- )", text, flags=re.MULTILINE)
    else:
        chunks = [text]

    files: list[dict] = []
    for chunk in chunks:
        chunk = chunk.strip("\n")
        if not chunk.strip():
            continue

        filename = fallback_filename
        plus_match = re.search(r"^\+\+\+ b?/?(\S+)", chunk, re.MULTILINE)
        diff_match = re.search(r"^diff --git a/(.+?) b/(.+)$", chunk, re.MULTILINE)
        if plus_match and plus_match.group(1) != "/dev/null":
            filename = plus_match.group(1)
        elif diff_match:
            filename = diff_match.group(2)

        status = "modified"
        if "new file mode" in chunk or chunk.startswith("--- /dev/null"):
            status = "added"
        elif "deleted file mode" in chunk or "+++ /dev/null" in chunk:
            status = "removed"

        additions = 0
        deletions = 0
        for line in chunk.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        files.append(
            {
                "filename": filename,
                "status": status,
                "additions": additions,
                "deletions": deletions,
                "patch": chunk,
            }
        )
    return files


@router.get("/commits")
def list_commits(
    repository_id: int | None = None,
    risk_level_filter: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(CommitRecord).order_by(CommitRecord.committed_at.desc())
    if repository_id:
        query = query.filter(CommitRecord.repository_id == repository_id)
    if risk_level_filter:
        query = query.filter(CommitRecord.risk_level == risk_level_filter)
    commits = query.limit(100).all()
    names = {repo.id: repo.name for repo in db.query(Repository).all()}
    return [commit_out(commit, names.get(commit.repository_id)) for commit in commits]


@router.get("/commits/{commit_id}")
def get_commit(commit_id: int, db: Session = Depends(get_db)):
    commit = db.get(CommitRecord, commit_id)
    if not commit:
        raise HTTPException(404, "Commit not found")
    repository = db.get(Repository, commit.repository_id)
    return commit_out(
        commit,
        repository.name if repository else None,
        include_files=True,
    )


@router.post("/commits/{commit_id}/review")
def review_commit(
    commit_id: int, payload: ReviewIn, db: Session = Depends(get_db)
):
    commit = db.get(CommitRecord, commit_id)
    if not commit:
        raise HTTPException(404, "Commit not found")
    commit.reviewed = payload.reviewed
    db.commit()
    db.refresh(commit)
    repository = db.get(Repository, commit.repository_id)
    return commit_out(commit, repository.name if repository else None, include_files=True)


@router.post("/repositories/{repo_id}/commits/import", status_code=201)
def import_diff(
    repo_id: int, payload: DiffImportIn, db: Session = Depends(get_db)
):
    repository = db.get(Repository, repo_id)
    if not repository:
        raise HTTPException(404, "Target not found")

    try:
        raw_files = parse_unified_diff(payload.diff_text, payload.filename or "changes.patch")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not raw_files:
        raise HTTPException(422, "No file changes found in that diff")

    diff_files: list[DiffFile] = []
    reasons: list[str] = []
    for item in raw_files:
        flags = file_flags(item["filename"], item["patch"])
        diff_files.append(
            DiffFile(
                filename=item["filename"],
                status=item["status"],
                additions=item["additions"],
                deletions=item["deletions"],
                patch=item["patch"],
                is_sensitive=bool(flags),
                sensitive_reasons=flags,
            )
        )
        for reason in flags:
            if reason not in reasons:
                reasons.append(reason)

    commit = CommitRecord(
        repository_id=repository.id,
        sha=(payload.sha or uuid.uuid4().hex)[:60],
        message=payload.message or "Imported change set",
        author=payload.author or "manual import",
        committed_at=datetime.now(timezone.utc),
        files_changed=len(diff_files),
        additions=sum(file.additions for file in diff_files),
        deletions=sum(file.deletions for file in diff_files),
        risk_level=risk_level(reasons),
        risk_reasons=reasons,
        files=diff_files,
    )
    db.add(commit)
    db.commit()
    db.refresh(commit)
    return commit_out(commit, repository.name, include_files=True)
