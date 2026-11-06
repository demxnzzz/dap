"""Token-aware GitHub archive fetching for the one-shot scan.

The GitHub token is read from the environment (``GITHUB_TOKEN``) and only ever
used as a request header. It is never echoed in responses, error text or logs.

Behaviour:
- repository metadata (default branch) is requested with the token when present;
- the archive is requested from the API tarball endpoint so the token is honoured;
- GitHub answers with a redirect to ``codeload.github.com``, which is followed
  WITHOUT the token so the credential cannot leak to a redirect target;
- rate limits, rejected tokens, private repositories and oversize archives map
  to actionable, secret-free errors.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from .github_sync import github_token

API_ROOT = "https://api.github.com"
USER_AGENT = "dap-bug-hunting-workbench"
API_VERSION = "2022-11-28"
MAX_ARCHIVE_BYTES = 60 * 1024 * 1024
REDIRECTS = {301, 302, 303, 307, 308}


class GitHubFetchError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _headers(token: str | None) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _rate_limited(response: httpx.Response) -> bool:
    return response.status_code == 429 or (
        response.status_code == 403
        and (
            response.headers.get("x-ratelimit-remaining") == "0"
            or "rate limit" in response.text[:400].lower()
        )
    )


def _rate_limit_error(response: httpx.Response, token: str | None) -> GitHubFetchError:
    retry_after = response.headers.get("retry-after")
    wait = f" Retry in about {retry_after} seconds." if retry_after else ""
    if token:
        return GitHubFetchError(
            "GitHub's API rate limit is exhausted for the configured token. "
            f"Wait for the reset window or use a token with more quota.{wait}",
            429,
        )
    return GitHubFetchError(
        "GitHub's anonymous API rate limit is exhausted. Add a GITHUB_TOKEN secret "
        f"to raise the limit, then retry.{wait}",
        429,
    )


def _not_found_error(token: str | None) -> GitHubFetchError:
    if token:
        return GitHubFetchError(
            "Repository not found, or the configured token cannot read it. Private "
            "repositories are not supported by the one-shot scan yet.",
            404,
        )
    return GitHubFetchError(
        "Repository not found. If it is private, add a GITHUB_TOKEN secret and retry; "
        "otherwise check the URL.",
        404,
    )


def _upstream_error(response: httpx.Response, token: str | None) -> GitHubFetchError:
    status = response.status_code
    if _rate_limited(response):
        return _rate_limit_error(response, token)
    if status == 404:
        return GitHubFetchError("GitHub could not find that repository or branch.", 404)
    if status == 401:
        if token:
            return GitHubFetchError(
                "GitHub rejected the configured GITHUB_TOKEN (401). Replace it with a "
                "valid token that can read this repository.",
                401,
            )
        return GitHubFetchError("GitHub refused the request (401).", 401)
    if status == 403:
        if token:
            return GitHubFetchError(
                "GitHub denied access (403). The token may lack read access, or the "
                "repository is private — private scans are not supported yet.",
                403,
            )
        return GitHubFetchError(
            "GitHub refused the request (403). Add a GITHUB_TOKEN secret and retry.",
            403,
        )
    if status >= 500:
        return GitHubFetchError(
            f"GitHub is unavailable right now (HTTP {status}). Retry shortly.", 502
        )
    return GitHubFetchError(
        f"GitHub responded {status} while fetching the repository archive.", 502
    )


def _read_archive(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            raise GitHubFetchError(
                "Repository archive is larger than 60 MB; scan a smaller repository.",
                413,
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _download_redirect(client: httpx.Client, location: str) -> tuple[bytes | None, GitHubFetchError | None]:
    """Fetch the archive redirect target without the token."""
    with client.stream("GET", location, headers={"User-Agent": USER_AGENT}) as response:
        if response.status_code == 200:
            return _read_archive(response), None
        return None, _upstream_error(response, None)


def _archive_for_ref(
    client: httpx.Client, owner: str, slug: str, ref: str, token: str | None
) -> tuple[bytes | None, GitHubFetchError | None]:
    url = f"{API_ROOT}/repos/{owner}/{slug}/tarball/{quote(ref, safe='')}"
    with client.stream("GET", url, headers=_headers(token)) as response:
        if response.status_code in REDIRECTS:
            location = response.headers.get("location")
            if not location:
                return None, GitHubFetchError(
                    "GitHub answered with a redirect without a target; retry shortly.",
                    502,
                )
            return _download_redirect(client, location)
        if response.status_code != 200:
            return None, _upstream_error(response, token)
        return _read_archive(response), None


def _default_branch(
    client: httpx.Client, owner: str, slug: str, token: str | None
) -> tuple[str | None, GitHubFetchError | None]:
    try:
        response = client.get(f"{API_ROOT}/repos/{owner}/{slug}", headers=_headers(token))
    except httpx.HTTPError as exc:
        raise GitHubFetchError(f"Could not reach GitHub: {exc}", 502)

    if response.status_code == 200:
        branch = (response.json() or {}).get("default_branch")
        return branch or None, None

    if _rate_limited(response):
        return None, _rate_limit_error(response, token)
    if response.status_code == 404:
        raise _not_found_error(token)

    error = _upstream_error(response, token)
    if error.status_code in (401, 403):
        raise error
    return None, error


def fetch_archive(
    owner: str, slug: str, token: str | None = None
) -> tuple[bytes, str]:
    """Return the tarball bytes and the branch they came from."""
    token = (token or "").strip() or None
    with httpx.Client(
        timeout=60.0,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        branch, meta_error = _default_branch(client, owner, slug, token)

        refs: list[str] = []
        for ref in (branch, "main", "master"):
            if ref and ref not in refs:
                refs.append(ref)

        last_error: GitHubFetchError | None = None
        for ref in refs:
            data, error = _archive_for_ref(client, owner, slug, ref, token)
            if data:
                return data, ref
            if error is not None and error.status_code in (401, 403, 429):
                raise error
            if error is not None:
                last_error = error

    if meta_error is not None:
        raise meta_error
    if last_error is not None and last_error.status_code != 404:
        raise last_error
    raise _not_found_error(token)


__all__ = ["GitHubFetchError", "fetch_archive", "github_token"]
