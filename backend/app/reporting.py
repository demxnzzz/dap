"""Markdown report rendering shared by the live preview and saved reports."""

from __future__ import annotations

from datetime import datetime, timezone


def _clean(value: str | None, fallback: str = "") -> str:
    value = (value or "").strip()
    return value or fallback


def _fenced(text: str) -> str:
    text = text.strip()
    if "```" in text:
        return text
    return "```\n" + text + "\n```"


def build_markdown(data: dict) -> str:
    title = _clean(data.get("title"), "Untitled finding")
    severity = _clean(data.get("severity"), "medium").lower()
    score = data.get("cvss_score")
    vector = _clean(data.get("cvss_vector"))
    platform = _clean(data.get("platform"), "HackerOne")
    status = _clean(data.get("status"), "draft")
    target = _clean(data.get("target"), "—")
    researcher = _clean(data.get("researcher"), "—")
    date = data.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    score_text = f"CVSS 3.1 · {score}" if score is not None else "not scored"

    lines = [
        f"# {title}",
        "",
        f"**Target:** {target}  ",
        f"**Researcher:** {researcher}  ",
        f"**Severity:** {severity.capitalize()} ({score_text})  ",
        f"**Platform:** {platform}  ",
        f"**Status:** {status}  ",
        f"**Date:** {date}",
        "",
    ]
    if vector:
        lines += [f"`{vector}`", ""]

    lines += ["## Summary", "", _clean(data.get("summary"), "_Add a short summary._"), ""]
    lines += [
        "## Steps to Reproduce",
        "",
        _fenced(_clean(data.get("steps"), "1. ...")),
        "",
    ]
    lines += ["## Root Cause", "", _clean(data.get("root_cause"), "_Add the root cause._"), ""]
    lines += ["## Impact", "", _clean(data.get("impact"), "_Describe the security impact._"), ""]
    lines += [
        "## Remediation",
        "",
        _clean(data.get("remediation"), "_Recommend a fix._"),
        "",
    ]

    references = _clean(data.get("references"))
    if references:
        bullet_lines = []
        for row in references.splitlines():
            row = row.strip().lstrip("-* ").strip()
            if row:
                bullet_lines.append(f"- {row}")
        lines += ["## References", "", "\n".join(bullet_lines), ""]

    return "\n".join(lines).rstrip() + "\n"
