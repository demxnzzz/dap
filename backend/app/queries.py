from sqlalchemy import func

from .models import Asset, CommitRecord, Finding, Report


def repository_counts(db, repo_id: int) -> dict:
    def count(model, *filters):
        return db.query(func.count(model.id)).filter(*filters).scalar() or 0

    return {
        "assets": count(Asset, Asset.repository_id == repo_id),
        "commits": count(CommitRecord, CommitRecord.repository_id == repo_id),
        "flagged_commits": count(
            CommitRecord,
            CommitRecord.repository_id == repo_id,
            CommitRecord.risk_level.in_(["high", "medium"]),
        ),
        "findings": count(Finding, Finding.repository_id == repo_id),
        "open_findings": count(
            Finding,
            Finding.repository_id == repo_id,
            Finding.status.in_(["new", "triaged", "confirmed"]),
        ),
        "reports": count(Report, Report.repository_id == repo_id),
    }
