"""Heuristics that decide which changed files deserve a closer hunting look."""

from __future__ import annotations

import re

SENSITIVE_PATH_HINTS = [
    (r"auth", "authentication code"),
    (r"login|signin|sign-in|logout", "login flow"),
    (r"session", "session handling"),
    (r"jwt|oauth|openid|saml", "token / identity protocol"),
    (r"token|apikey|api-key|secret|credential", "secret or token handling"),
    (r"crypt|cipher|hash|password|passwd", "cryptography / password handling"),
    (r"permission|role|acl|authoriz|admin", "authorization or admin surface"),
    (r"payment|billing|invoice|checkout", "payment logic"),
    (r"config|\.env|settings|dockerfile|compose", "environment / deployment config"),
    (r"sql|migration|schema\.prisma", "database access or schema"),
    (r"upload|file", "file handling"),
    (r"middleware", "request middleware"),
    (r"routes?|controllers?|handlers?|views?|endpoints?", "request routing"),
]

RISKY_PATTERNS = [
    (r"eval\s*\(", "dynamic code evaluation"),
    (r"exec\s*\(", "dynamic code execution"),
    (r"subprocess|child_process|os\.system", "shell invocation"),
    (r"shell\s*=\s*True", "shell=True"),
    (r"verify\s*=\s*False", "TLS verification disabled"),
    (r"dangerouslySetInnerHTML|innerHTML\s*=", "raw HTML injection sink"),
    (r"pickle\.loads|yaml\.load\s*\(|unserialize\s*\(", "unsafe deserialization"),
    (r"SELECT\s+.+\+|\+\s*['\"].*(?:WHERE|SELECT)", "string-built SQL"),
    (r"\.raw\s*\(|execute\s*\(\s*f?['\"].*(?:SELECT|INSERT|UPDATE|DELETE)", "raw SQL execution"),
    (r"md5|sha1\s*\(", "weak hash primitive"),
    (r"CORS|Access-Control-Allow-Origin", "CORS policy change"),
    (r"csrf", "CSRF protection change"),
    (r"bcrypt|argon2|scrypt", "password hashing"),
]


def flag_path(filename: str) -> list[str]:
    lowered = (filename or "").lower()
    reasons: list[str] = []
    for pattern, label in SENSITIVE_PATH_HINTS:
        if re.search(pattern, lowered) and label not in reasons:
            reasons.append(label)
    return reasons


def flag_patch(patch: str) -> list[str]:
    added = "\n".join(
        line for line in (patch or "").splitlines() if line.startswith("+")
    )
    reasons: list[str] = []
    for pattern, label in RISKY_PATTERNS:
        if re.search(pattern, added, re.IGNORECASE) and label not in reasons:
            reasons.append(label)
    return reasons


def file_flags(filename: str, patch: str) -> list[str]:
    reasons = flag_path(filename)
    for reason in flag_patch(patch):
        if reason not in reasons:
            reasons.append(reason)
    return reasons


def risk_level(reasons: list[str]) -> str:
    if len(reasons) >= 3:
        return "high"
    if len(reasons) >= 1:
        return "medium"
    return "low"
