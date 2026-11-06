"""GitHub repository sync: commits, diffs and attack-surface extraction."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from .extractors import extract_routes, is_source_file
from .models import Asset, CommitRecord, DiffFile, Repository
from .security import file_flags, risk_level

API_ROOT = "https://api.github.com"
USER_AGENT = "dap-bug-hunting-workbench"


class GitHubError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def github_token() -> str | None:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    return token or None


def parse_repo_url(url: str) -> tuple[str, str]:
    match = re.search(r"github\.com[/:]+([\w.\-]+)/([\w.\-]+)", url or "")
    if not match:
        raise GitHubError(
            "Enter a GitHub repository URL such as https://github.com/owner/repo", 422
        )
    owner, slug = match.group(1), match.group(2)
    if slug.endswith(".git"):
        slug = slug[:-4]
    return owner, slug


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return _utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _utcnow()


async def _get(client: httpx.AsyncClient, path: str, accept: str | None = None):
    headers = {"Accept": accept} if accept else None
    response = await client.get(path, headers=headers)
    if response.status_code == 403 and "rate limit" in response.text.lower():
        raise GitHubError(
            "GitHub API rate limit reached. Add a GITHUB_TOKEN secret to raise the limit.",
            429,
        )
    if response.status_code >= 400:
        detail = response.text[:200].replace("\n", " ")
        raise GitHubError(f"GitHub responded {response.status_code}: {detail}", 502)
    return response


def build_diff_files(raw_files: list[dict]) -> tuple[list[DiffFile], list[str]]:
    rows: list[DiffFile] = []
    all_reasons: list[str] = []
    for item in raw_files:
        filename = item.get("filename") or "unknown"
        patch = item.get("patch") or ""
        flags = file_flags(filename, patch)
        rows.append(
            DiffFile(
                filename=filename,
                status=item.get("status") or "modified",
                additions=int(item.get("additions") or 0),
                deletions=int(item.get("deletions") or 0),
                patch=patch,
                is_sensitive=bool(flags),
                sensitive_reasons=flags,
            )
        )
        for reason in flags:
            if reason not in all_reasons:
                all_reasons.append(reason)
    return rows, all_reasons


def upsert_assets(db: Session, repository: Repository, routes: list[dict]) -> tuple[int, int]:
    added = 0
    updated = 0
    for route in routes:
        existing = (
            db.query(Asset)
            .filter_by(
                repository_id=repository.id,
                method=route["method"],
                path=route["path"],
                file_path=route["file_path"],
            )
            .first()
        )
        if existing:
            existing.params = sorted(set(existing.params or []) | set(route["params"]))
            existing.last_seen = _utcnow()
            existing.framework = route["framework"] or existing.framework
            updated += 1
        else:
            db.add(
                Asset(
                    repository_id=repository.id,
                    method=route["method"],
                    path=route["path"],
                    file_path=route["file_path"],
                    framework=route["framework"],
                    params=route["params"],
                )
            )
            added += 1
    return added, updated


async def sync_repository(
    db: Session, repository: Repository, token: str | None = None
) -> dict:
    owner, slug = parse_repo_url(repository.url)
    repository.owner = owner
    repository.repo_slug = slug

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    commits_added = 0
    files_scanned = 0
    assets_added = 0
    assets_updated = 0

    async with httpx.AsyncClient(
        base_url=API_ROOT, headers=headers, timeout=25.0
    ) as client:
        meta = await _get(client, f"/repos/{owner}/{slug}")
        repository.default_branch = (meta or {}).get("default_branch") or "main"

        per_page = 10 if token else 6
        payload = await _get(
            client, f"/repos/{owner}/{slug}/commits?per_page={per_page}"
        )
        commits = payload.json() if isinstance(payload.json(), list) else []
        known = {
            row[0]
            for row in db.query(CommitRecord.sha)
            .filter(CommitRecord.repository_id == repository.id)
            .all()
        }

        for item in commits:
            sha = item.get("sha")
            if not sha or sha in known:
                continue
            detail = await _get(client, f"/repos/{owner}/{slug}/commits/{sha}")
            body = detail.json()
            files, reasons = build_diff_files(body.get("files") or [])
            commit_info = body.get("commit") or {}
            db.add(
                CommitRecord(
                    repository_id=repository.id,
                    sha=sha[:60],
                    message=(commit_info.get("message") or "")[:4000],
                    author=((commit_info.get("author") or {}).get("name") or "unknown")[
                        :160
                    ],
                    committed_at=_parse_datetime(
                        (commit_info.get("author") or {}).get("date")
                    ),
                    files_changed=len(files),
                    additions=sum(file.additions for file in files),
                    deletions=sum(file.deletions for file in files),
                    risk_level=risk_level(reasons),
                    risk_reasons=reasons,
                    files=files,
                )
            )
            known.add(sha)
            commits_added += 1

        tree_response = await _get(
            client,
            f"/repos/{owner}/{slug}/git/trees/{quote(repository.default_branch)}?recursive=1",
        )
        tree = tree_response.json().get("tree") or []
        candidates = [
            blob
            for blob in tree
            if blob.get("type") == "blob"
            and is_source_file(blob.get("path", ""))
            and (blob.get("size") or 0) < 200_000
        ]
        limit = 40 if token else 15
        routes: list[dict] = []
        for blob in candidates[:limit]:
            path = blob["path"]
            try:
                content_response = await _get(
                    client,
                    f"/repos/{owner}/{slug}/contents/{quote(path)}?ref={quote(repository.default_branch)}",
                    accept="application/vnd.github.raw",
                )
            except GitHubError:
                continue
            routes.extend(extract_routes(path, content_response.text))
            files_scanned += 1

        assets_added, assets_updated = upsert_assets(db, repository, routes)

    repository.last_synced_at = _utcnow()
    db.commit()
    return {
        "commits_added": commits_added,
        "files_scanned": files_scanned,
        "assets_added": assets_added,
        "assets_updated": assets_updated,
        "default_branch": repository.default_branch,
    }
