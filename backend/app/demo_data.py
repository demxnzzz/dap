"""A realistic seeded workspace so the workbench can be explored immediately."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .cvss import evaluate
from .example_model import apply_example
from .models import Asset, CommitRecord, Finding, Report, Repository
from .reporting import build_markdown
from .security import file_flags, risk_level
from .sarif_ingest import dedupe_key

DEMO_NAME = "acme-store (demo)"

COMMITS = [
    {
        "sha": "9f2c1ab47de0c6b1a4bd2f7f3f3c9d51b8e60a12",
        "days_ago": 1,
        "author": "m.okafor",
        "message": "feat(auth): add password reset flow with JWT tokens",
        "files": [
            (
                "src/routes/auth.js",
                "modified",
                24,
                2,
                r"""@@ -1,6 +1,28 @@
 const express = require('express');
 const jwt = require('jsonwebtoken');
 const router = express.Router();
 
+router.post('/api/auth/reset-request', async (req, res) => {
+  const { email } = req.body;
+  const user = await db('users').where({ email }).first();
+  if (!user) return res.json({ ok: true });
+  const token = jwt.sign({ sub: user.id, scope: 'reset' }, 'acme-dev-secret', {
+    expiresIn: '30d',
+  });
+  await mailer.sendReset(user.email, token);
+  res.json({ ok: true });
+});
+
+router.post('/api/auth/reset-confirm', async (req, res) => {
+  const { token, password } = req.body;
+  const claims = jwt.verify(token, 'acme-dev-secret');
+  await db('users').where({ id: claims.sub }).update({ password: hash(password) });
+  res.json({ ok: true });
+});
+
 module.exports = router;
""",
            ),
            (
                "src/config/session.js",
                "modified",
                4,
                1,
                r"""@@ -1,4 +1,7 @@
 module.exports = {
-  cookieSecret: process.env.COOKIE_SECRET,
+  cookieSecret: process.env.COOKIE_SECRET || 'dev-cookie-secret',
+  secure: false,
+  sameSite: 'none',
 };
""",
            ),
        ],
    },
    {
        "sha": "4d81be0e3a9a5c7f1d2b6a8c0e4f9b3d5c7a1e20",
        "days_ago": 3,
        "author": "j.ramirez",
        "message": "fix(orders): look up an order by id for support tooling",
        "files": [
            (
                "src/routes/orders.js",
                "modified",
                12,
                0,
                r"""@@ -18,6 +18,18 @@ router.get('/api/orders', auth, async (req, res) => {
   res.json(rows);
 });
 
+router.get('/api/orders/:orderId', async (req, res) => {
+  const sql = "SELECT * FROM orders WHERE id = " + req.query.orderId;
+  const rows = await db.raw(sql);
+  res.json(rows[0]);
+});
+
+router.post('/api/orders/:orderId/refund', async (req, res) => {
+  await db('orders').where({ id: req.params.orderId }).update({ refunded: true });
+  res.json({ ok: true });
+});
+
 module.exports = router;
""",
            ),
            (
                "src/middleware/auth.js",
                "modified",
                1,
                3,
                r"""@@ -6,9 +6,7 @@ module.exports = async function auth(req, res, next) {
   if (!req.headers.authorization) {
     return res.status(401).json({ error: 'missing token' });
   }
-  if (req.headers['x-internal-service']) {
-    return next();
-  }
   if (!verify(req.headers.authorization)) {
     return res.status(401).json({ error: 'invalid token' });
   }
""",
            ),
        ],
    },
    {
        "sha": "c73ae92561f0d4b8a7c6e5f4d3c2b1a098765432",
        "days_ago": 5,
        "author": "s.dupont",
        "message": "chore(admin): add bulk export endpoint",
        "files": [
            (
                "src/routes/admin.js",
                "modified",
                18,
                0,
                r"""@@ -30,6 +30,24 @@ router.get('/api/admin/users', adminOnly, async (req, res) => {
   res.json(users);
 });
 
+router.get('/api/admin/export', async (req, res) => {
+  const format = req.query.format || 'csv';
+  const { exec } = require('child_process');
+  exec(`./scripts/export.sh ${format}`, (err, stdout) => {
+    if (err) return res.status(500).send(err.message);
+    res.type('text/plain').send(stdout);
+  });
+});
+
 module.exports = router;
""",
            ),
            (
                ".github/workflows/deploy.yml",
                "modified",
                5,
                2,
                r"""@@ -12,8 +12,11 @@ jobs:
       - uses: actions/checkout@v4
       - name: Build image
         run: docker build -t acme/store:${{ github.sha }} .
-      - name: Deploy
+      - name: Deploy (skip verification)
         run: |
-          ./scripts/verify.sh
           ./scripts/deploy.sh ${{ github.sha }}
""",
            ),
        ],
    },
    {
        "sha": "2b91f0c4d5e6a7b8c9d0e1f2a3b4c5d6e7f80911",
        "days_ago": 8,
        "author": "m.okafor",
        "message": "docs: refresh onboarding guide",
        "files": [
            (
                "README.md",
                "modified",
                6,
                2,
                r"""@@ -1,4 +1,8 @@
 # acme store
 
+## Onboarding
+Run `npm install`, then `npm run dev` to boot the storefront.
+
 Local development uses docker compose.
""",
            ),
        ],
    },
]

ASSETS = [
    ("GET", "/api/orders/:orderId", "src/routes/orders.js", "express", ["orderId", "include"]),
    ("POST", "/api/orders/:orderId/refund", "src/routes/orders.js", "express", ["orderId"]),
    ("GET", "/api/orders", "src/routes/orders.js", "express", ["page", "limit", "status"]),
    ("POST", "/api/auth/reset-request", "src/routes/auth.js", "express", ["email"]),
    ("POST", "/api/auth/reset-confirm", "src/routes/auth.js", "express", ["token", "password"]),
    ("POST", "/api/auth/login", "src/routes/auth.js", "express", ["email", "password"]),
    ("GET", "/api/admin/export", "src/routes/admin.js", "express", ["format"]),
    ("GET", "/api/admin/users", "src/routes/admin.js", "express", ["page", "role"]),
    ("GET", "/api/users/:id", "src/routes/users.js", "express", ["id"]),
    ("PUT", "/api/users/:id", "src/routes/users.js", "express", ["id"]),
    ("GET", "/api/products", "src/routes/products.js", "express", ["q", "sort"]),
    ("GET", "/api/products/:slug", "src/routes/products.js", "express", ["slug"]),
    ("POST", "/api/checkout", "src/routes/checkout.js", "express", ["cartId", "coupon"]),
    ("POST", "/api/webhooks/stripe", "src/routes/webhooks.js", "express", []),
    ("GET", "/admin/debug", "service/admin.py", "flask", []),
    ("POST", "/login", "service/auth.py", "flask", ["username", "password"]),
    ("GET", "/api/v1/users/<int:user_id>", "service/users.py", "flask", ["user_id"]),
    ("GET", "/api/v2/assets/{asset_id}", "service/assets.py", "fastapi", ["asset_id"]),
]

FINDINGS = [
    {
        "title": "Hardcoded JWT signing secret in password reset flow",
        "rule_id": "js.jwt.security.hardcoded-secret",
        "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "file_path": "src/routes/auth.js",
        "line": 8,
        "status": "confirmed",
        "description": (
            "The reset and confirmation endpoints sign and verify JWTs with the "
            "literal string 'acme-dev-secret'. Anyone with repository access — or "
            "anyone who reads a leaked build artifact — can mint valid reset tokens "
            "for arbitrary user ids and take over accounts."
        ),
    },
    {
        "title": "SQL injection in support order lookup",
        "rule_id": "js.lang.security.audit.sqli.node-knex-sqli",
        "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "file_path": "src/routes/orders.js",
        "line": 22,
        "status": "confirmed",
        "description": (
            "GET /api/orders/:orderId concatenates req.query.orderId into a raw SQL "
            "statement. The route is unauthenticated and returns the first row, so a "
            "UNION payload can read arbitrary tables."
        ),
    },
    {
        "title": "Command injection in admin bulk export",
        "rule_id": "js.child-process.security.audit.command-injection",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "file_path": "src/routes/admin.js",
        "line": 34,
        "status": "triaged",
        "description": (
            "The export endpoint interpolates the ?format= query parameter into "
            "child_process.exec. A shell metacharacter payload runs as the API user."
        ),
    },
    {
        "title": "Reset tokens valid for 30 days",
        "rule_id": "js.jwt.security.audit.excessive-token-lifetime",
        "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "file_path": "src/routes/auth.js",
        "line": 12,
        "status": "new",
        "description": (
            "Password reset JWTs expire after 30 days, far beyond the usual 15-60 "
            "minute window, keeping leaked links useful for a month."
        ),
    },
    {
        "title": "Flask debug console exposed in admin service",
        "rule_id": "python.flask.security.audit.debug-enabled",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "file_path": "service/admin.py",
        "line": 61,
        "status": "new",
        "description": (
            "app.run(debug=True) is reachable from the public ingress. The Werkzeug "
            "console allows arbitrary code execution once a PIN is derived."
        ),
    },
    {
        "title": "Weak password hashing with MD5",
        "rule_id": "python.lang.security.audit.md5-used-as-password-hash",
        "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "file_path": "service/auth.py",
        "line": 27,
        "status": "false_positive",
        "description": (
            "hashlib.md5 is used when storing user passwords. The value is unsalted "
            "and fast to brute force if the users table leaks."
        ),
    },
    {
        "title": "Outdated express dependency (4.16.0)",
        "rule_id": "js.dependencies.audit.outdated-express",
        "severity": "low",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "file_path": "package.json",
        "line": 14,
        "status": "new",
        "description": "express 4.16.0 has known advisories fixed in later 4.x releases.",
    },
]


def _seed_commits(db: Session, repository: Repository) -> None:
    now = datetime.now(timezone.utc)
    for entry in COMMITS:
        files = []
        reasons: list[str] = []
        from .models import DiffFile

        for filename, status, additions, deletions, patch in entry["files"]:
            flags = file_flags(filename, patch)
            files.append(
                DiffFile(
                    filename=filename,
                    status=status,
                    additions=additions,
                    deletions=deletions,
                    patch=patch,
                    is_sensitive=bool(flags),
                    sensitive_reasons=flags,
                )
            )
            for reason in flags:
                if reason not in reasons:
                    reasons.append(reason)
        db.add(
            CommitRecord(
                repository_id=repository.id,
                sha=entry["sha"],
                message=entry["message"],
                author=entry["author"],
                committed_at=now - timedelta(days=entry["days_ago"]),
                files_changed=len(files),
                additions=sum(file.additions for file in files),
                deletions=sum(file.deletions for file in files),
                risk_level=risk_level(reasons),
                risk_reasons=reasons,
                reviewed=entry["days_ago"] > 6,
                files=files,
            )
        )


def _seed_assets(db: Session, repository: Repository) -> None:
    now = datetime.now(timezone.utc)
    for index, (method, path, file_path, framework, params) in enumerate(ASSETS):
        db.add(
            Asset(
                repository_id=repository.id,
                method=method,
                path=path,
                file_path=file_path,
                framework=framework,
                params=params,
                first_seen=now - timedelta(days=30 - index),
                last_seen=now - timedelta(days=1),
            )
        )


def _seed_findings(db: Session, repository: Repository) -> dict[str, int]:
    ids: dict[str, int] = {}
    now = datetime.now(timezone.utc)
    for index, entry in enumerate(FINDINGS):
        vector = entry["cvss"]
        scored = evaluate(vector)
        finding = Finding(
            repository_id=repository.id,
            title=entry["title"],
            description=entry["description"],
            source="sarif",
            rule_id=entry["rule_id"],
            severity=entry["severity"],
            status=entry["status"],
            file_path=entry["file_path"],
            line=entry["line"],
            cvss_vector=scored["vector"],
            cvss_score=scored["score"],
            dedupe_key=dedupe_key(entry["rule_id"], entry["file_path"], entry["line"]),
            occurrences=1 + (index % 3),
            created_at=now - timedelta(days=6 - index),
            updated_at=now - timedelta(days=index),
        )
        db.add(finding)
        db.flush()
        ids[entry["rule_id"]] = finding.id
    return ids


def _seed_report(db: Session, repository: Repository, finding_id: int, finding: dict) -> None:
    scored = evaluate(finding["cvss"])
    data = {
        "title": finding["title"],
        "target": "acme-store",
        "researcher": "you@dap.local",
        "summary": finding["description"],
        "steps": (
            "1. Sign in as a low-privileged customer.\n"
            "2. Capture the reset email for your own account and decode the JWT.\n"
            "3. Re-sign the payload with the secret 'acme-dev-secret' for another user id.\n"
            "4. POST /api/auth/reset-confirm with the forged token and a new password.\n"
            "5. Observe the victim account now authenticates with the chosen password."
        ),
        "root_cause": (
            "The reset flow commits a hardcoded signing secret in source control instead "
            "of loading it from the environment, so token integrity is not secret."
        ),
        "impact": (
            "Full account takeover of any user, including administrators. Attackers can "
            "reset credentials, read order history and reach admin endpoints."
        ),
        "remediation": (
            "Rotate the JWT secret, load it from a secret manager, shorten reset token "
            "lifetime to 15 minutes and bind tokens to a single-use nonce stored server-side."
        ),
        "references": "https://cwe.mitre.org/data/definitions/798.html\nhttps://cwe.mitre.org/data/definitions/640.html",
        "cvss_vector": scored["vector"],
        "cvss_score": scored["score"],
        "severity": scored["severity"],
        "platform": "HackerOne",
        "status": "draft",
    }
    data["markdown"] = build_markdown(data)
    db.add(
        Report(
            repository_id=repository.id,
            finding_id=finding_id,
            title=data["title"],
            target=data["target"],
            researcher=data["researcher"],
            summary=data["summary"],
            steps=data["steps"],
            root_cause=data["root_cause"],
            impact=data["impact"],
            remediation=data["remediation"],
            references=data["references"],
            cvss_vector=data["cvss_vector"],
            cvss_score=data["cvss_score"],
            severity=data["severity"],
            platform=data["platform"],
            status=data["status"],
            markdown=data["markdown"],
        )
    )


def load_demo(db: Session) -> tuple[Repository, bool]:
    existing = db.query(Repository).filter(Repository.name == DEMO_NAME).first()
    if existing:
        return existing, False

    repository = Repository(
        name=DEMO_NAME,
        url="https://github.com/acme/acme-store",
        platform="github",
        source_type="demo",
        default_branch="main",
        owner="acme",
        repo_slug="acme-store",
        last_synced_at=datetime.now(timezone.utc) - timedelta(hours=6),
    )
    db.add(repository)
    db.flush()

    _seed_commits(db, repository)
    _seed_assets(db, repository)
    finding_ids = _seed_findings(db, repository)
    _seed_report(
        db, repository, finding_ids[FINDINGS[0]["rule_id"]], FINDINGS[0]
    )
    apply_example(db, repository)
    db.commit()
    return repository, True
