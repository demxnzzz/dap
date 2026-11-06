# DAP — Bug Hunting Workbench

An attack-surface workspace for security researchers. It turns a codebase into
something you can hunt against: risky commits, an inventory of routes and
parameters, SARIF findings and submission-ready reports.

## Modules

| Module | What it does |
| --- | --- |
| **Targets** | Add a GitHub repository, sync recent commits + diffs, or work offline with the seeded demo. |
| **Commit review** | Diffs are split per file and scored by sensitive-path and risky-sink heuristics (auth, secrets, SQL, shell, deserialization…). Mark changes reviewed. |
| **Asset inventory** | Routes, HTTP methods and parameters extracted from Express, FastAPI, Flask, Django, Spring, Rails and Go source. |
| **Findings** | SARIF 2.1.0 ingestion with rule/location deduplication, plus manual findings, statuses and CVSS vectors. |
| **Reports** | Structured writeup (summary, steps, root cause, impact, remediation), CVSS v3.1 calculator, Markdown export. |

## Stack

- **API** — FastAPI + SQLAlchemy 2, PostgreSQL 16.
- **Web** — React 18 + Vite, hand-written CSS (no UI framework).
- **Runtime** — Docker Compose, dev servers with live reload.

## Run it

```bash
docker compose -f docker-compose.base44.yml up -d --build
```

- Web UI: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health: `GET /api/health`

The web dev server proxies `/api` to the API service, so the browser only talks
to port 3000 (single origin, no CORS setup).

## First run

1. Open the UI and press **Load demo workspace** to seed a small, clearly-labelled
   demo target with commits, endpoints, findings and one draft report.
2. Or go to **Targets** and add a GitHub repository, then **Sync now**.

## GitHub sync

`POST /api/repositories/{id}/sync` uses the GitHub REST API:

- commit list + per-commit file patches → `commits` / `diff_files`
- repository tree + raw file contents → route extraction → `assets`

Public repositories sync without credentials (6 commits, 15 files per sync,
60 requests/hour). Set a `GITHUB_TOKEN` secret with read access for private
repositories and larger batches (10 commits, 40 files). Nothing else is required
to boot.

## Offline path

No token, no network? You can still use everything:

- **Changes → Import diff** accepts a unified diff (git patch) and runs the same
  risk heuristics.
- **Assets → Scan source** accepts source files or a pasted snippet and indexes
  routes locally. No code is executed — extraction is regex based.

## CVSS

`POST /api/cvss/evaluate` implements the CVSS v3.1 base-score equation
(`roundup`, scope-change reweighting, severity bands). v4.0 is not implemented.

## Tests / checks

There is no test runner configured yet. The quickest end-to-end check:

```bash
curl -s localhost:3000/api/health
curl -s -X POST localhost:3000/api/demo/load
curl -s localhost:3000/api/stats
```

`GET /api/health` is used by the Compose healthcheck.
