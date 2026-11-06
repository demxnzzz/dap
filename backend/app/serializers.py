from __future__ import annotations

from .models import Asset, CommitRecord, DiffFile, Finding, Report, Repository


def _iso(value):
    return value.isoformat() if value else None


def repo_out(repo: Repository, counts: dict | None = None) -> dict:
    return {
        "id": repo.id,
        "name": repo.name,
        "url": repo.url,
        "platform": repo.platform,
        "source_type": repo.source_type,
        "default_branch": repo.default_branch,
        "owner": repo.owner,
        "repo_slug": repo.repo_slug,
        "last_synced_at": _iso(repo.last_synced_at),
        "created_at": _iso(repo.created_at),
        "counts": counts or {},
    }


def asset_out(asset: Asset, repo_name: str | None = None) -> dict:
    return {
        "id": asset.id,
        "repository_id": asset.repository_id,
        "repository_name": repo_name,
        "method": asset.method,
        "path": asset.path,
        "file_path": asset.file_path,
        "framework": asset.framework,
        "params": asset.params or [],
        "first_seen": _iso(asset.first_seen),
        "last_seen": _iso(asset.last_seen),
    }


def file_out(file: DiffFile) -> dict:
    return {
        "id": file.id,
        "filename": file.filename,
        "status": file.status,
        "additions": file.additions,
        "deletions": file.deletions,
        "patch": file.patch,
        "is_sensitive": file.is_sensitive,
        "sensitive_reasons": file.sensitive_reasons or [],
    }


def commit_out(
    commit: CommitRecord,
    repo_name: str | None = None,
    include_files: bool = False,
) -> dict:
    data = {
        "id": commit.id,
        "repository_id": commit.repository_id,
        "repository_name": repo_name,
        "sha": commit.sha,
        "short_sha": commit.sha[:7],
        "message": commit.message,
        "author": commit.author,
        "committed_at": _iso(commit.committed_at),
        "files_changed": commit.files_changed,
        "additions": commit.additions,
        "deletions": commit.deletions,
        "risk_level": commit.risk_level,
        "risk_reasons": commit.risk_reasons or [],
        "reviewed": commit.reviewed,
    }
    if include_files:
        data["files"] = [file_out(file) for file in commit.files]
    return data


def finding_out(finding: Finding, repo_name: str | None = None) -> dict:
    return {
        "id": finding.id,
        "repository_id": finding.repository_id,
        "repository_name": repo_name,
        "title": finding.title,
        "description": finding.description,
        "source": finding.source,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "status": finding.status,
        "file_path": finding.file_path,
        "line": finding.line,
        "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score,
        "occurrences": finding.occurrences,
        "created_at": _iso(finding.created_at),
        "updated_at": _iso(finding.updated_at),
    }


def report_out(report: Report, include_markdown: bool = False) -> dict:
    data = {
        "id": report.id,
        "repository_id": report.repository_id,
        "finding_id": report.finding_id,
        "title": report.title,
        "target": report.target,
        "researcher": report.researcher,
        "summary": report.summary,
        "steps": report.steps,
        "root_cause": report.root_cause,
        "impact": report.impact,
        "remediation": report.remediation,
        "references": report.references,
        "cvss_vector": report.cvss_vector,
        "cvss_score": report.cvss_score,
        "severity": report.severity,
        "platform": report.platform,
        "status": report.status,
        "created_at": _iso(report.created_at),
        "updated_at": _iso(report.updated_at),
    }
    if include_markdown:
        data["markdown"] = report.markdown
    return data
