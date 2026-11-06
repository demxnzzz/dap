from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..cvss import evaluate
from ..db import get_db
from ..models import Finding, Repository
from ..sarif_ingest import parse_sarif
from ..serializers import finding_out

router = APIRouter(prefix="/api", tags=["findings"])

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"new", "triaged", "confirmed", "false_positive", "reported", "fixed"}


class SarifIn(BaseModel):
    repository_id: int
    sarif: dict


class FindingIn(BaseModel):
    repository_id: int
    title: str
    description: str = ""
    severity: str = "medium"
    file_path: str = ""
    line: int | None = None
    cvss_vector: str = ""


class FindingPatch(BaseModel):
    status: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    cvss_vector: str | None = None


def _apply_cvss(finding: Finding, vector: str) -> None:
    vector = (vector or "").strip()
    if not vector:
        return
    try:
        scored = evaluate(vector)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    finding.cvss_vector = scored["vector"]
    finding.cvss_score = scored["score"]
    finding.severity = scored["severity"]


@router.get("/findings")
def list_findings(
    repository_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Finding).order_by(Finding.created_at.desc())
    if repository_id:
        query = query.filter(Finding.repository_id == repository_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if source:
        query = query.filter(Finding.source == source)
    findings = query.limit(500).all()
    names = {repo.id: repo.name for repo in db.query(Repository).all()}
    return [finding_out(finding, names.get(finding.repository_id)) for finding in findings]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    repository = db.get(Repository, finding.repository_id)
    return finding_out(finding, repository.name if repository else None)


@router.post("/findings", status_code=201)
def create_finding(payload: FindingIn, db: Session = Depends(get_db)):
    repository = db.get(Repository, payload.repository_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    if not (payload.title or "").strip():
        raise HTTPException(422, "A title is required")

    severity = payload.severity if payload.severity in VALID_SEVERITIES else "medium"
    finding = Finding(
        repository_id=repository.id,
        title=payload.title.strip()[:400],
        description=payload.description or "",
        source="manual",
        severity=severity,
        file_path=payload.file_path or "",
        line=payload.line,
    )
    _apply_cvss(finding, payload.cvss_vector)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding_out(finding, repository.name)


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: int, payload: FindingPatch, db: Session = Depends(get_db)
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    if payload.status is not None:
        if payload.status not in VALID_STATUSES:
            raise HTTPException(422, f"Unknown status: {payload.status}")
        finding.status = payload.status
    if payload.severity is not None:
        if payload.severity not in VALID_SEVERITIES:
            raise HTTPException(422, f"Unknown severity: {payload.severity}")
        finding.severity = payload.severity
    if payload.title is not None:
        finding.title = payload.title.strip()[:400]
    if payload.description is not None:
        finding.description = payload.description
    if payload.cvss_vector is not None:
        try:
            _apply_cvss(finding, payload.cvss_vector)
        except HTTPException:
            raise
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)
    repository = db.get(Repository, finding.repository_id)
    return finding_out(finding, repository.name if repository else None)


@router.delete("/findings/{finding_id}", status_code=204)
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    db.delete(finding)
    db.commit()
    return None


@router.post("/sarif")
def import_sarif(payload: SarifIn, db: Session = Depends(get_db)):
    repository = db.get(Repository, payload.repository_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    try:
        parsed = parse_sarif(payload.sarif)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not parsed:
        raise HTTPException(422, "That SARIF file contains no results")

    created = 0
    merged = 0
    for item in parsed:
        existing = (
            db.query(Finding).filter(Finding.dedupe_key == item["dedupe_key"]).first()
        )
        if existing:
            existing.occurrences += 1
            existing.updated_at = datetime.now(timezone.utc)
            merged += 1
            continue
        db.add(
            Finding(
                repository_id=repository.id,
                title=item["title"],
                description=item["description"],
                source="sarif",
                rule_id=item["rule_id"],
                severity=item["severity"],
                file_path=item["file_path"],
                line=item["line"],
                cvss_score=item["score"],
                dedupe_key=item["dedupe_key"],
            )
        )
        created += 1
    db.commit()
    return {
        "results": len(parsed),
        "created": created,
        "merged": merged,
        "repository": repository.name,
    }
