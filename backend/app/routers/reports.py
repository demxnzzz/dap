from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..cvss import evaluate
from ..db import get_db
from ..models import Report, Repository
from ..reporting import build_markdown
from ..serializers import report_out

router = APIRouter(prefix="/api", tags=["reports"])


class ReportFields(BaseModel):
    title: str = "Untitled finding"
    target: str = ""
    researcher: str = ""
    summary: str = ""
    steps: str = ""
    root_cause: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""
    cvss_vector: str = ""
    platform: str = "HackerOne"
    status: str = "draft"


class ReportIn(ReportFields):
    repository_id: int
    finding_id: int | None = None


def _score(vector: str) -> tuple[str, float | None, str]:
    vector = (vector or "").strip()
    if not vector:
        return "", None, "medium"
    try:
        scored = evaluate(vector)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return scored["vector"], scored["score"], scored["severity"]


def _rendered(payload: dict, date: str | None = None) -> dict:
    vector, score, severity = _score(payload.get("cvss_vector", ""))
    data = {
        **payload,
        "cvss_vector": vector,
        "cvss_score": score,
        "severity": severity,
        "date": date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    data["markdown"] = build_markdown(data)
    return data


@router.get("/reports")
def list_reports(repository_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(Report).order_by(Report.updated_at.desc())
    if repository_id:
        query = query.filter(Report.repository_id == repository_id)
    return [report_out(report) for report in query.limit(200).all()]


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return report_out(report, include_markdown=True)


@router.post("/reports/preview")
def preview_report(payload: ReportFields):
    data = _rendered(payload.model_dump())
    return {
        "markdown": data["markdown"],
        "cvss_vector": data["cvss_vector"],
        "cvss_score": data["cvss_score"],
        "severity": data["severity"],
    }


@router.post("/reports", status_code=201)
def create_report(payload: ReportIn, db: Session = Depends(get_db)):
    repository = db.get(Repository, payload.repository_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    data = _rendered(payload.model_dump(exclude={"repository_id", "finding_id"}))
    report = Report(
        repository_id=repository.id,
        finding_id=payload.finding_id,
        title=data["title"] or "Untitled finding",
        target=data["target"],
        researcher=data["researcher"],
        summary=data["summary"],
        steps=data["steps"],
        root_cause=data["root_cause"],
        impact=data["impact"],
        remediation=data["remediation"],
        references=data["references"],
        cvss_vector=data["cvss_vector"],
        cvss_score=data["cvss_score"],
        severity=data["severity"],
        platform=data["platform"],
        status=data["status"],
        markdown=data["markdown"],
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report_out(report, include_markdown=True)


@router.put("/reports/{report_id}")
def update_report(report_id: int, payload: ReportFields, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    date = report.created_at.strftime("%Y-%m-%d") if report.created_at else None
    data = _rendered(payload.model_dump(), date=date)
    report.title = data["title"] or "Untitled finding"
    report.target = data["target"]
    report.researcher = data["researcher"]
    report.summary = data["summary"]
    report.steps = data["steps"]
    report.root_cause = data["root_cause"]
    report.impact = data["impact"]
    report.remediation = data["remediation"]
    report.references = data["references"]
    report.cvss_vector = data["cvss_vector"]
    report.cvss_score = data["cvss_score"]
    report.severity = data["severity"]
    report.platform = data["platform"]
    report.status = data["status"]
    report.markdown = data["markdown"]
    report.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)
    return report_out(report, include_markdown=True)


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    db.delete(report)
    db.commit()
    return None


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
def report_markdown(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    filename = "".join(
        char if char.isalnum() or char in "-_" else "-"
        for char in report.title.lower()
    ).strip("-")
    return PlainTextResponse(
        report.markdown or "",
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{filename or "report"}.md"'
        },
    )
