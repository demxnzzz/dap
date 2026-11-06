"""CVSS v3.1 base score computation (spec-compliant)."""

from __future__ import annotations

from typing import Any

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

VECTOR_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
ALLOWED = {
    "AV": set(AV),
    "AC": set(AC),
    "PR": set(PR_UNCHANGED),
    "UI": set(UI),
    "S": {"U", "C"},
    "C": set(CIA),
    "I": set(CIA),
    "A": set(CIA),
}


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup."""
    integer = int(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (integer // 10000 + 1) / 10.0


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "medium"
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def parse_vector(vector: str) -> dict[str, str]:
    raw = (vector or "").strip()
    if raw.startswith("CVSS:3.1/"):
        raw = raw[len("CVSS:3.1/") :]
    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid metric segment: {part}")
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        if key not in ALLOWED:
            raise ValueError(f"unknown metric: {key}")
        if value not in ALLOWED[key]:
            raise ValueError(f"invalid value for {key}: {value}")
        metrics[key] = value
    missing = [key for key in VECTOR_ORDER if key not in metrics]
    if missing:
        raise ValueError("missing metrics: " + ", ".join(missing))
    return metrics


def evaluate(vector: str) -> dict[str, Any]:
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = (
        8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr_table[metrics["PR"]] * UI[metrics["UI"]]
    )

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))

    normalized = "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in VECTOR_ORDER)
    return {
        "vector": normalized,
        "score": score,
        "severity": severity_from_score(score),
        "metrics": metrics,
        "impact": round(impact, 3),
        "exploitability": round(exploitability, 3),
    }
