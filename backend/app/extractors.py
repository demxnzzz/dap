"""Static route extraction across common web frameworks.

Deliberately library-free: regex over source text is fast, dependency-free and
good enough to build a useful attack-surface inventory from a repo scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".java",
    ".rb",
    ".go",
    ".php",
    ".kt",
}

PATH_PARAM_PATTERNS = [
    re.compile(r"\{(\w+)\}"),
    re.compile(r":(\w+)"),
    re.compile(r"<(?:\w+:)?(\w+)>"),
]

QUERY_HINT_PATTERNS = [
    re.compile(r"(?:request\.args\.get|request\.query_params\.get|request\.GET\.get)\(\s*[\"'](\w+)[\"']"),
    re.compile(r"req\.query\.(\w+)"),
    re.compile(r"request\.query\[\s*[\"'](\w+)[\"']\s*\]"),
    re.compile(r"@RequestParam\(\s*(?:value\s*=\s*)?[\"'](\w+)[\"']"),
    re.compile(r"searchParams\.get\(\s*[\"'](\w+)[\"']"),
]


@dataclass
class RouteRule:
    framework: str
    pattern: re.Pattern
    method_group: int | None
    path_group: int
    default_method: str
    methods_in: int | None = None


ROUTE_RULES = [
    RouteRule(
        "fastapi",
        re.compile(
            r"@(?:app|router|api_router|bp|blueprint)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        1,
        2,
        "GET",
    ),
    RouteRule(
        "flask",
        re.compile(r"@(?:app|bp|blueprint|api)\.route\(\s*[\"']([^\"']+)[\"']([^\n]*)"),
        None,
        1,
        "GET",
        methods_in=2,
    ),
    RouteRule(
        "express",
        re.compile(
            r"\b(?:app|router|server|api|fastify)\.(get|post|put|patch|delete|all)\(\s*[`'\"]([^`'\"]+)[`'\"]",
            re.IGNORECASE,
        ),
        1,
        2,
        "GET",
    ),
    RouteRule(
        "spring",
        re.compile(
            r"@(Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        1,
        2,
        "GET",
    ),
    RouteRule(
        "spring",
        re.compile(
            r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']([^\n]*)",
            re.IGNORECASE,
        ),
        None,
        1,
        "GET",
        methods_in=2,
    ),
    RouteRule(
        "django",
        re.compile(r"\b(?:path|re_path)\(\s*r?[\"']([^\"']+)[\"']"),
        None,
        1,
        "GET",
    ),
    RouteRule(
        "rails",
        re.compile(r"^\s*(get|post|put|patch|delete)\s+[\"']([^\"']+)[\"']", re.MULTILINE | re.IGNORECASE),
        1,
        2,
        "GET",
    ),
    RouteRule(
        "go",
        re.compile(r"\.(GET|POST|PUT|PATCH|DELETE|HandleFunc)\(\s*\"([^\"]+)\""),
        1,
        2,
        "GET",
    ),
]


def _normalize_method(method: str) -> str:
    method = (method or "GET").upper()
    if method == "ALL":
        return "ANY"
    if method == "HANDLEFUNC":
        return "GET"
    if method.startswith("GET") and method != "GET":
        return "GET"
    return method


def _methods_for(rule: RouteRule, match: re.Match, text: str) -> list[str]:
    if rule.method_group is not None:
        return [_normalize_method(match.group(rule.method_group))]
    if rule.methods_in is not None:
        tail = match.group(rule.methods_in) or ""
        found = re.findall(r"RequestMethod\.(\w+)", tail)
        found += re.findall(r"methods\s*=\s*\[([^\]]*)\]", tail)
        flat: list[str] = []
        for chunk in found:
            flat.extend(re.findall(r"[A-Za-z]+", chunk))
        methods = [_normalize_method(word) for word in flat if word.lower() in {
            "get", "post", "put", "patch", "delete", "head", "options"
        }]
        return sorted(set(methods)) or [rule.default_method]
    return [rule.default_method]


def _params(path: str, text: str, position: int) -> list[str]:
    names: list[str] = []
    for pattern in PATH_PARAM_PATTERNS:
        for name in pattern.findall(path):
            if name not in names:
                names.append(name)
    window = text[position : position + 1600]
    for pattern in QUERY_HINT_PATTERNS:
        for name in pattern.findall(window):
            if name not in names:
                names.append(name)
    return names


def extract_routes(path: str, content: str) -> list[dict]:
    """Return [{method, path, file_path, framework, params}] for one source file."""
    routes: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for rule in ROUTE_RULES:
        for match in rule.pattern.finditer(content):
            endpoint = (match.group(rule.path_group) or "").strip()
            if not endpoint or endpoint.startswith(("http://", "https://")):
                continue
            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
            for method in _methods_for(rule, match, content):
                key = (method, endpoint)
                if key in seen:
                    continue
                seen.add(key)
                routes.append(
                    {
                        "method": method,
                        "path": endpoint,
                        "file_path": path,
                        "framework": rule.framework,
                        "params": _params(endpoint, content, match.start()),
                    }
                )
    return routes


def is_source_file(path: str) -> bool:
    lowered = (path or "").lower()
    return any(lowered.endswith(ext) for ext in SOURCE_EXTENSIONS)
