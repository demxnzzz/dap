"""SARIF 2.1.0 ingestion: flatten tool runs into finding candidates."""

from __future__ import annotations

import hashlib
from typing import Any

from .cvss import severity_from_score

LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}


def _first_location(result: dict) -> tuple[str, int | None]:
    locations = result.get("locations") or []
    if not locations:
        return "", None
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri") or ""
    uri = uri.replace("file://", "").lstrip("./")
    line = (physical.get("region") or {}).get("startLine")
    return uri, line


def dedupe_key(rule_id: str, file_path: str, line: int | None) -> str:
    raw = f"{rule_id}|{file_path}|{line if line is not None else 0}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def parse_sarif(document: dict) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise ValueError("SARIF document must be a JSON object")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document has no 'runs' array")

    findings: list[dict[str, Any]] = []
    for run in runs:
        tool = ((run or {}).get("tool") or {}).get("driver") or {}
        rules = {str(rule.get("id")): rule for rule in (tool.get("rules") or []) if rule.get("id")}

        for result in run.get("results") or []:
            rule_id = str(
                result.get("ruleId")
                or ((result.get("rule") or {}).get("id"))
                or "unknown-rule"
            )
            rule = rules.get(rule_id, {})
            props = rule.get("properties") or {}
            message = result.get("message") or {}
            description = message.get("text") or message.get("markdown") or ""

            level = (
                result.get("level")
                or (rule.get("defaultConfiguration") or {}).get("level")
                or "warning"
            )

            raw_score = props.get("security-severity")
            score: float | None = None
            if raw_score not in (None, ""):
                try:
                    score = float(raw_score)
                except (TypeError, ValueError):
                    score = None

            severity = (
                severity_from_score(score)
                if score is not None
                else LEVEL_TO_SEVERITY.get(str(level).lower(), "medium")
            )

            file_path, line = _first_location(result)
            title = (
                (rule.get("shortDescription") or {}).get("text")
                or rule.get("name")
                or rule_id
            )
            full_description = (rule.get("fullDescription") or {}).get("text") or description

            findings.append(
                {
                    "rule_id": rule_id,
                    "title": str(title)[:400],
                    "description": str(full_description or description),
                    "severity": severity,
                    "file_path": file_path,
                    "line": line,
                    "score": score,
                    "dedupe_key": dedupe_key(rule_id, file_path, line),
                }
            )
    return findings
