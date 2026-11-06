"""One-shot flow: repository URL in, full assessment with PoCs out."""

from __future__ import annotations

import io
import re
import tarfile
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from .cvss import evaluate
from .extractors import extract_routes, is_source_file
from .github_archive import GitHubFetchError, fetch_archive
from .github_sync import upsert_assets
from .models import Finding, Report, Repository
from .queries import repository_counts
from .reporting import build_markdown
from .sarif_ingest import dedupe_key
from .serializers import finding_out, repo_out, report_out
from .signals import SignalDef, scan_text

MAX_ARCHIVE_BYTES = 60 * 1024 * 1024
MAX_FILE_BYTES = 250_000
MAX_FILES = 800
MAX_FINDINGS = 80
MAX_REPORTS = 15

USER_AGENT = "dap-bug-hunting-workbench"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BOUNTY = {
    "critical": (2000, 10000),
    "high": (800, 4000),
    "medium": (200, 1000),
    "low": (50, 300),
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".rb",
    ".go", ".php", ".cs", ".rs", ".scala", ".sh", ".bash", ".yml", ".yaml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env",
    ".example", ".sql",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", "coverage", ".next",
    "__pycache__", "venv", ".venv", "site-packages", "target", "out",
}


class ScanError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _client() -> httpx.Client:
    """Client for non-GitHub hosts (GitLab); it never carries the GitHub token."""
    return httpx.Client(
        headers={"User-Agent": USER_AGENT},
        timeout=60.0,
        follow_redirects=True,
    )


def _read_archive(client: httpx.Client, url: str) -> bytes | None:
    try:
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                return None
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ScanError(
                        "Repository archive is larger than 60 MB; scan a smaller repository.",
                        413,
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except httpx.HTTPError:
        return None


def _fetch_github(
    owner: str, slug: str, token: str | None
) -> tuple[dict[str, str], str]:
    try:
        data, branch = fetch_archive(owner, slug, token)
    except GitHubFetchError as exc:
        raise ScanError(exc.message, exc.status_code)
    files = _extract(data)
    if not files:
        raise ScanError(
            "The repository archive contained no scannable source files.", 422
        )
    return files, branch


def _fetch_gitlab(
    client: httpx.Client, owner: str, slug: str
) -> tuple[dict[str, str], str]:
    project = quote(f"{owner}/{slug}", safe="")
    try:
        response = client.get(f"https://gitlab.com/api/v4/projects/{project}")
    except httpx.HTTPError as exc:
        raise ScanError(f"Could not reach GitLab: {exc}", 502)
    if response.status_code == 404:
        raise ScanError(
            "Repository not found on GitLab. Private projects are not supported in the "
            "one-shot scan yet.",
            404,
        )
    if response.status_code >= 400:
        raise ScanError("GitLab rejected the request. Check the repository URL.", 502)
    branch = (response.json() or {}).get("default_branch") or "main"
    for candidate in [name for name in [branch, "main", "master"] if name]:
        url = (
            f"https://gitlab.com/{owner}/{slug}/-/archive/{candidate}/"
            f"{slug}-{candidate}.tar.gz"
        )
        data = _read_archive(client, url)
        if data:
            files = _extract(data)
            if files:
                return files, candidate
    raise ScanError("Could not download the GitLab archive for that branch.", 502)


def _split_repo_url(url: str) -> tuple[str, str, str]:
    text = (url or "").strip()
    github = re.search(r"github\.com[/:]+([\w.\-]+)/([\w.\-]+)", text)
    if github:
        slug = github.group(2)
        if slug.endswith(".git"):
            slug = slug[:-4]
        return "github", github.group(1), slug

    gitlab = re.search(r"gitlab\.com[/:]([^\s?#]+)", text)
    if gitlab:
        parts = [part for part in gitlab.group(1).split("/") if part]
        if len(parts) >= 2:
            slug = parts[-1]
            if slug.endswith(".git"):
                slug = slug[:-4]
            return "gitlab", "/".join(parts[:-1]), slug

    raise ScanError(
        "Paste a GitHub or GitLab repository URL, for example "
        "https://github.com/owner/repo",
        422,
    )


def _fetch(
    url: str, token: str | None
) -> tuple[str, str, str, dict[str, str], str]:
    platform, owner, slug = _split_repo_url(url)
    if platform == "gitlab":
        with _client() as client:
            files, branch = _fetch_gitlab(client, owner, slug)
    else:
        files, branch = _fetch_github(owner, slug, token)
    return platform, owner, slug, files, branch


def _scannable(path: str, size: int) -> bool:
    if size > MAX_FILE_BYTES:
        return False
    lowered = path.lower()
    if any(part in SKIP_DIRS for part in lowered.split("/")[:-1]):
        return False
    name = lowered.rsplit("/", 1)[-1]
    if name in {"dockerfile", "makefile", "procfile"} or name.startswith(".env"):
        return True
    return any(name.endswith(ext) for ext in SCAN_EXTENSIONS)


def _extract(data: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise ScanError(f"The repository archive could not be read: {exc}", 502)

    with archive:
        for member in archive:
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                continue
            name = member.name.split("/", 1)[-1] if "/" in member.name else member.name
            if not name or ".." in name.split("/"):
                continue
            if not _scannable(name, member.size):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            raw = handle.read()
            if b"\x00" in raw[:1024]:
                continue
            files[name] = raw.decode("utf-8", "ignore")
            if len(files) >= MAX_FILES:
                break
    return files


def _route_for(path: str, routes_by_file: dict[str, dict]) -> dict | None:
    return routes_by_file.get(path)


def _format_route(route: dict | None) -> str:
    if not route:
        return "no statically declared route in this file"
    return f"`{route['method']} {route['path']}`"


def _money(severity: str) -> tuple[int, int]:
    return BOUNTY.get(severity, (0, 0))


def _fmt_money(low: int, high: int) -> str:
    if not high:
        return "not estimated"
    return f"${low:,}–${high:,}"


def _upsert_report(
    db: Session,
    repository: Repository,
    title: str,
    payload: dict,
    markdown: str,
) -> tuple[Report, bool]:
    existing = (
        db.query(Report)
        .filter(Report.repository_id == repository.id, Report.title == title)
        .first()
    )
    created = existing is None
    report = existing or Report(repository_id=repository.id, title=title)
    report.target = payload.get("target", "")
    report.researcher = payload.get("researcher", "")
    report.summary = payload.get("summary", "")
    report.steps = payload.get("steps", "")
    report.root_cause = payload.get("root_cause", "")
    report.impact = payload.get("impact", "")
    report.remediation = payload.get("remediation", "")
    report.references = payload.get("references", "")
    report.cvss_vector = payload.get("cvss_vector", "")
    report.cvss_score = payload.get("cvss_score")
    report.severity = payload.get("severity", "medium")
    report.platform = payload.get("platform", "HackerOne")
    report.status = payload.get("status", "draft")
    report.markdown = markdown
    report.updated_at = datetime.now(timezone.utc)
    if created:
        db.add(report)
    db.flush()
    return report, created


def _finding_payload(
    repository: Repository,
    hit: dict,
    scored: dict,
    platform: str,
    researcher: str,
) -> dict:
    rule: SignalDef = hit["rule"]
    route = hit.get("route")
    target = repository.url or f"https://{repository.platform}.com/{repository.owner}/{repository.repo_slug}"
    return {
        "title": f"{rule.title} — {hit['file']}:{hit['line']}"[:390],
        "target": target,
        "researcher": researcher,
        "summary": (
            f"{rule.summary}\n\n"
            f"**Evidence** — `{hit['file']}:{hit['line']}`\n\n"
            f"```\n{hit['snippet']}\n```\n\n"
            f"**Route** — {_format_route(route)}"
        ),
        "steps": rule.poc(hit),
        "root_cause": rule.root_cause,
        "impact": rule.impact,
        "remediation": rule.remediation,
        "references": (
            f"https://cwe.mitre.org/data/definitions/{rule.cwe}.html\n{rule.owasp}"
        ),
        "cvss_vector": scored["vector"],
        "cvss_score": scored["score"],
        "severity": scored["severity"],
        "platform": platform,
        "status": "draft",
    }


def _assessment_markdown(
    repository: Repository,
    branch: str,
    files_scanned: int,
    routes: list[dict],
    findings: list[tuple[Finding, dict]],
    platform: str,
    researcher: str,
) -> str:
    owner, slug = repository.owner, repository.repo_slug
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    counts = {key: 0 for key in ("critical", "high", "medium", "low")}
    low_total = high_total = 0
    for finding, _ in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        low, high = _money(finding.severity)
        low_total += low
        high_total += high

    mix = ", ".join(f"{counts[key]} {key}" for key in counts if counts[key]) or "none"
    top_routes = routes[:20]
    detailed = findings[:10]

    lines = [
        f"# Full security assessment — {owner}/{slug}",
        "",
        f"**Target:** {repository.url}  ",
        f"**Branch:** `{branch}`  ",
        f"**Platform:** {platform}  ",
        f"**Researcher:** {researcher or '—'}  ",
        f"**Generated:** {now}  ",
        f"**Scope:** {files_scanned} source and configuration files read from the branch.",
        "",
        "## Executive summary",
        "",
        f"Static review of `{owner}/{slug}` produced **{len(findings)} candidate finding(s)** "
        f"({mix}) across **{len(routes)} declared route(s)**.",
        "",
        f"Rough bounty potential for this set: **{_fmt_money(low_total, high_total)}** "
        "(platform- and program-dependent; a triager sets the real value).",
        "",
        "> These are static candidates, not confirmed exploits. Exercise every proof of "
        "concept against an environment you are authorized to test before submitting.",
        "",
        "## Attack surface",
        "",
    ]
    if top_routes:
        lines += ["| Method | Path | Framework | Source |", "| --- | --- | --- | --- |"]
        for route in top_routes:
            lines.append(
                f"| {route['method']} | `{route['path']}` | {route['framework']} | "
                f"`{route['file_path']}` |"
            )
        if len(routes) > len(top_routes):
            lines.append("")
            lines.append(f"_…{len(routes) - len(top_routes)} more routes in the inventory._")
    else:
        lines.append("No HTTP routes were recognised statically.")
    lines.append("")

    if not detailed:
        lines += [
            "## Findings",
            "",
            "No high-signal patterns matched in this pass. That is not proof the code is "
            "secure — combine this with authenticated, runtime testing.",
            "",
        ]
    else:
        lines += ["## Findings", ""]
        for index, (finding, hit) in enumerate(detailed, 1):
            rule: SignalDef = hit["rule"]
            low, high = _money(finding.severity)
            lines += [
                f"### {index}. {rule.title}",
                "",
                f"- **Severity:** {finding.severity.upper()} · CVSS {finding.cvss_score}"
                f" (`{finding.cvss_vector}`)",
                f"- **Location:** `{hit['file']}:{hit['line']}`",
                f"- **Rule:** `{rule.rule_id}` · CWE-{rule.cwe}",
                f"- **Route:** {_format_route(hit.get('route'))}",
                f"- **Estimated bounty:** {_fmt_money(low, high)}",
                "",
                "**Evidence**",
                "",
                f"```\n{hit['snippet']}\n```",
                "",
                "**PoC (verify before submitting)**",
                "",
                rule.poc(hit),
                "",
                f"**Impact:** {rule.impact}",
                "",
                f"**Fix:** {rule.remediation}",
                "",
            ]
        if len(findings) > len(detailed):
            lines += [
                f"_{len(findings) - len(detailed)} further findings were scored and are "
                "listed in the Findings view._",
                "",
            ]

    lines += [
        "## Remediation roadmap",
        "",
        "1. Rotate every secret found above and remove it from history.",
        "2. Fix injection sinks with parameterised queries, argument arrays and schema validation.",
        "3. Turn off debug mode and disable wildcard CORS in deployed configuration.",
        "4. Add these rules (SAST + secret scanning) to CI so regressions fail the build.",
        "",
        "## Method and limitations",
        "",
        "- Heuristic static review of the default branch: route extraction plus pattern "
        "matching over source and configuration files.",
        "- Routes are parsed from framework decorators and router calls; dynamically built "
        "routes are not visible this way.",
        "- A finding means the pattern is present, not that the path is reachable — confirm "
        "each PoC before reporting.",
        "- The absence of findings is not evidence that the target is secure.",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def run_scan(
    db: Session,
    url: str,
    researcher: str = "",
    platform: str = "HackerOne",
    max_reports: int = 8,
    token: str | None = None,
) -> dict:
    host, owner, slug, files, branch = _fetch(url, token)

    max_reports = max(1, min(int(max_reports or 8), MAX_REPORTS))

    repository = (
        db.query(Repository)
        .filter(
            Repository.owner == owner,
            Repository.repo_slug == slug,
            Repository.platform == host,
            Repository.source_type != "demo",
        )
        .first()
    )
    if not repository:
        repository = Repository(
            name=f"{owner}/{slug}"[:160],
            url=f"https://{host}.com/{owner}/{slug}",
            platform=host,
            source_type=host,
            default_branch=branch,
            owner=owner,
            repo_slug=slug,
        )
        db.add(repository)
        db.flush()
    repository.default_branch = branch

    routes: list[dict] = []
    raw_hits: list[dict] = []
    for path, content in files.items():
        if is_source_file(path):
            routes.extend(extract_routes(path, content))
        if len(raw_hits) < MAX_FINDINGS:
            raw_hits.extend(scan_text(path, content))

    routes_by_file: dict[str, dict] = {}
    for route in routes:
        routes_by_file.setdefault(route["file_path"], route)

    hits: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for hit in raw_hits[:MAX_FINDINGS]:
        key = (hit["rule"].rule_id, hit["file"], hit["line"])
        if key in seen:
            continue
        seen.add(key)
        hit["route"] = _route_for(hit["file"], routes_by_file)
        hits.append(hit)

    assets_added, assets_updated = upsert_assets(db, repository, routes)

    findings: list[tuple[Finding, dict]] = []
    now = datetime.now(timezone.utc)
    for hit in hits:
        rule: SignalDef = hit["rule"]
        scored = evaluate(rule.cvss)
        key = dedupe_key(f"scan:{repository.id}:{rule.rule_id}", hit["file"], hit["line"])
        finding = db.query(Finding).filter(Finding.dedupe_key == key).first()
        description = (
            f"{rule.summary}\n\nEvidence: {hit['file']}:{hit['line']}\n\n"
            f"{hit['snippet']}\n\nRoute: {_format_route(hit.get('route'))}"
        )
        if finding:
            finding.occurrences += 1
            finding.title = f"{rule.title} — {hit['file']}:{hit['line']}"[:400]
            finding.description = description
            finding.severity = scored["severity"]
            finding.cvss_vector = scored["vector"]
            finding.cvss_score = scored["score"]
            finding.updated_at = now
        else:
            finding = Finding(
                repository_id=repository.id,
                title=f"{rule.title} — {hit['file']}:{hit['line']}"[:400],
                description=description,
                source="scan",
                rule_id=rule.rule_id,
                severity=scored["severity"],
                status="new",
                file_path=hit["file"],
                line=hit["line"],
                cvss_vector=scored["vector"],
                cvss_score=scored["score"],
                dedupe_key=key,
                occurrences=1,
            )
            db.add(finding)
            db.flush()
        findings.append((finding, hit))

    findings.sort(
        key=lambda pair: (
            -SEVERITY_ORDER.get(pair[0].severity, 0),
            -(pair[0].cvss_score or 0),
            pair[1]["file"],
        )
    )

    report_rows: list[Report] = []
    created_reports = 0
    for finding, hit in findings[:max_reports]:
        rule = hit["rule"]
        scored = {
            "vector": finding.cvss_vector,
            "score": finding.cvss_score,
            "severity": finding.severity,
        }
        payload = _finding_payload(repository, hit, scored, platform, researcher)
        payload["finding_id"] = finding.id
        markdown = build_markdown({**payload, "date": now.strftime("%Y-%m-%d")})
        report, created = _upsert_report(db, repository, payload["title"], payload, markdown)
        report.finding_id = finding.id
        report_rows.append(report)
        created_reports += int(created)

    summary_markdown = _assessment_markdown(
        repository, branch, len(files), routes, findings, platform, researcher
    )
    counts = {key: 0 for key in ("critical", "high", "medium", "low")}
    low_total = high_total = 0
    for finding, _ in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        low, high = _money(finding.severity)
        low_total += low
        high_total += high

    summary_payload = {
        "title": f"Full security assessment — {owner}/{slug}"[:390],
        "target": repository.url,
        "researcher": researcher,
        "summary": (
            f"Static review of {len(files)} files produced {len(findings)} candidate "
            f"finding(s) across {len(routes)} declared routes. Rough bounty potential "
            f"{_fmt_money(low_total, high_total)}."
        ),
        "steps": "\n\n".join(
            f"### {rule.title} (`{hit['file']}:{hit['line']}`)\n\n{rule.poc(hit)}"
            for (_, hit) in findings[:max_reports]
            for rule in [hit["rule"]]
        )
        or "No candidate findings in this pass.",
        "root_cause": "Combined root causes are listed per finding below.",
        "impact": f"Combined candidate impact: {counts}.",
        "remediation": (
            "Rotate exposed secrets, parameterise every query, remove shell interpolation, "
            "disable debug mode and allowlist CORS origins."
        ),
        "references": "\n".join(
            f"https://cwe.mitre.org/data/definitions/{hit['rule'].cwe}.html"
            for (_, hit) in findings[:max_reports]
        ),
        "cvss_vector": findings[0][0].cvss_vector if findings else "",
        "cvss_score": findings[0][0].cvss_score if findings else None,
        "severity": findings[0][0].severity if findings else "info",
        "platform": platform,
        "status": "draft",
    }
    summary_payload["title"] = summary_payload["title"][:390]
    summary_report, summary_created = _upsert_report(
        db, repository, summary_payload["title"], summary_payload, summary_markdown
    )
    created_reports += int(summary_created)

    repository.last_synced_at = now
    db.commit()
    db.refresh(repository)
    for report in [*report_rows, summary_report]:
        db.refresh(report)

    return {
        "repository": repo_out(repository, repository_counts(db, repository.id)),
        "scan": {
            "branch": branch,
            "files_scanned": len(files),
            "routes_found": len(routes),
            "assets_added": assets_added,
            "assets_updated": assets_updated,
            "findings_found": len(findings),
            "reports_written": len(report_rows) + 1,
            "reports_created": created_reports,
            "severity_counts": counts,
            "bounty_estimate": _fmt_money(low_total, high_total),
            "bounty_low": low_total,
            "bounty_high": high_total,
            "platform": platform,
            "github_auth": "token" if (host == "github" and token) else "anonymous",
        },
        "summary_report_id": summary_report.id,
        "summary_markdown": summary_markdown,
        "reports": [report_out(report) for report in report_rows],
        "findings": [finding_out(finding, repository.name) for finding, _ in findings[:15]],
    }
