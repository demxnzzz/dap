# Agent setup notes

## Runtime

Everything runs via `docker-compose.base44.yml`:

- `db` — postgres:16-alpine, data in the `dap_pgdata` volume.
- `api` — built from `backend/Dockerfile`, source bind-mounted at `/workspace/backend`,
  `uvicorn --reload` on 8000. Tables are created by `Base.metadata.create_all` on startup,
  so no migration step is needed.
- `web` — node:22-alpine, repo bind-mounted at `/workspace`, Vite dev server on 3000.
  `node_modules` lives in the `web_node_modules` volume and is installed on first boot.

Start: `docker compose -f docker-compose.base44.yml up -d --build`

## Non-obvious behaviour

- The UI talks to `/api` only; Vite proxies it to `http://api:8000`. Do not add CORS —
  single-origin is deliberate.
- `BASE44_PREVIEW_MODE` is only read by `frontend/vite.config.js` to extend the dev-server
  host allowlist with `.<BASE44_SANDBOX_HOST_DOMAIN>`; unset behaviour is unchanged.
- `GITHUB_TOKEN` is optional (`env_file: /run/base44/app.env`, last entry). Without it sync
  uses unauthenticated GitHub endpoints with small batch sizes. Never put it under
  Compose `environment:` — that would shadow the dashboard secret.
- The demo workspace is a normal repository row (`source_type=demo`); sync is disabled for it.
- CVSS v3.1 scoring lives in `backend/app/cvss.py` and is the single source of truth
  (`POST /api/cvss/evaluate`, report preview/save). Do not duplicate the formula client-side.
- SARIF dedupe key = sha256(ruleId | file | line). Re-uploading a report increments
  `occurrences` instead of duplicating findings.

## Verification

- `curl -s localhost:3000/api/health` → `{"status":"ok"}`
- `curl -s -X POST localhost:3000/api/demo/load` seeds the demo target.
- `curl -s localhost:3000/api/stats` → counts used by the dashboard.
- UI routes: `/`, `/targets`, `/changes`, `/assets`, `/findings`, `/reports`, `/reports/new`.

## Sandbox quirks

- Write bind mounts work; the Vite watcher uses polling (`usePolling: true`) because
  inotify is unreliable over the bind mount.
- `frontend/package-lock.json` is generated inside the container on first install; if
  dependencies change, rebuild or remove the `web_node_modules` volume.
