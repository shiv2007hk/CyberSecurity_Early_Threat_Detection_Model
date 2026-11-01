# Deployment and operations

## Requirements

- Python 3.12+
- Node.js 20+ for building the SPA
- SQLite for zero-setup deployments, or PostgreSQL for concurrent production use
- A reverse proxy (Caddy, nginx, or a managed edge) terminating TLS

## Build

```bash
# from the repository root
python -m venv .venv
.venv/Scripts/activate            # Windows; use source .venv/bin/activate elsewhere
pip install -r backend/requirements.txt

cd frontend
npm ci
npm run build
cd ..
```

`frontend/dist` is served automatically by FastAPI when present. Build the frontend before starting the API in a single-process deployment.

## Configure

Copy `backend/.env.example` to `backend/.env` and set at minimum:

```ini
APP_ENV=production
APP_URL=https://cyberguard.example.com
JWT_SECRET_KEY=<random 48+ byte value>
DATABASE_URL=postgresql+psycopg://<user>:<password>@<host>:5432/<database>
DEEPSEEK_API_KEY=<key from the model provider console>
ENABLE_LIVE_THREAT_FEEDS=false
```

Set the two seeding flags described in the environment reference to `false` on any deployment that must start from an empty database.

Generate a secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Environment reference

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | `development` | `production` disables the seeded-account endpoint and interactive API docs, and requires a strong JWT secret |
| `APP_NAME` | `CYBERGUARD` | Display name reported by the API index and health payload |
| `APP_URL` / `API_BASE_URL` | localhost | Used for links and CORS defaults |
| `DATABASE_URL` | SQLite file | For PostgreSQL, install `psycopg[binary]` and use a `postgresql+psycopg://` URL |
| `JWT_SECRET_KEY` | insecure dev value | Must be replaced in any shared environment |
| `ACCESS_TOKEN_MINUTES` | `720` | JWT lifetime |
| `<corpus seeding flag>` | `true` | Loads the initial intelligence corpus into an empty database at startup |
| `<seeded-content flag>` | `true` | Gates the seeded corpus together with the flag above; set `false` where only imported and connector-retrieved records may exist |
| `ENABLE_LIVE_THREAT_FEEDS` | `true` | Enables outbound connector calls; set `false` for an air-gapped deployment |
| `NVD_API_KEY`, `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` | empty | Server-side only; never returned to the browser |
| `CISA_KEV_ENABLED`, `EPSS_ENABLED`, `MITRE_ATTACK_ENABLED` | `true` | Connector toggles |
| `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `DEEPSEEK_MODEL` | empty, `https://api.deepseek.com`, `deepseek-chat` | Aegis AI chat; see AI provider configuration below |
| `AI_PROVIDER`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `HUGGINGFACE_API_TOKEN` | empty | Optional enrichment providers; classification and scoring do not depend on them |
| `ENABLE_EMAIL_ALERTS`, `SMTP_*`, `EMAIL_FROM` | disabled | Notification preferences are stored even when SMTP is unavailable |
| `CORS_ORIGINS` | localhost origins | Comma-separated allow-list |

Both seeding flags must be `true` for the corpus to load; with either one off, a new database stays empty. The seeded-account endpoint under `/api/auth` returns 404 when `APP_ENV=production` or when seeded content is disabled, so seeded operator credentials are not discoverable on a deployed instance. Rotate those passwords before the first sign-in regardless.

### AI provider configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | empty | Bearer key for the DeepSeek chat-completions API. Read on the backend only; never written to a response body, never sent to the browser |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Completions host. Validated as `https`; plain `http` is accepted only for a localhost proxy, because the key travels in the request header |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model used for replies, conversation titles and the status probe |

A chat turn posts the system prompt plus the bounded retrieved-record block to `POST {DEEPSEEK_BASE_URL}/chat/completions` with `stream: true`, and relays the deltas to the console as Server-Sent Events. Timeout, output-token cap, temperature and retry count are read from the same configuration block in `backend/app/config.py`.

With no key set, the chat returns a configuration error and generates no reply; the rest of the platform is unaffected. Chat turns carry their own rate budget because they spend provider credit. `GET /api/chat/status` reports the configured model and host plus the last probe result — the key is never part of that payload.

## Run

```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Use a process manager (systemd, supervisord, container orchestrator) to keep it running. For SQLite, keep a single worker; for PostgreSQL, multiple workers are supported.

### Reverse proxy sketch

```caddy
cyberguard.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8000
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}
```

The application sets its own security headers; the proxy should not strip them.

Aegis AI replies arrive as Server-Sent Events, so buffering must stay off on that path: the application sends `X-Accel-Buffering: no` and `no-transform`, and an nginx or Traefik front end should disable response buffering for `/api/chat`.

## Health and observability

- `GET /api/system/health` — database check, version and timestamp.
- `GET /api/public/overview` — corpus counts, source composition and connector provenance.
- `GET /api/chat/status` — configured provider model and host, plus the last probe result; the key is never included.
- Application logs are written to the standard error stream as `timestamp level logger message`; route them to a log collector if they must be retained.
- Admin → Settings shows environment flags, connector configuration state, table counts and classifier evaluation history.
- Admin → Audit shows the append-only action trail with CSV export.

## Data lifecycle

- The SQLite database file is created under `backend/` on first start. Back it up by copying the file while the API is stopped, or by using SQLite's online backup API.
- Records loaded by `backend/app/seed.py` carry a provenance flag and are grouped under their own origin in the interface. Clearing them means resetting the corpus; do not do this in an environment where imported or connector-retrieved records exist.
- Scenario runs and scans append records and audit entries. They never delete data.
- Chat threads are owned by the user who started them. Each stored turn keeps its citation payload and retrieved-record count rather than a copy of the records; deleting a conversation or a user removes the thread, not the cited records.
- To start from an empty database, stop the API, move the database file aside, and restart with seeding enabled. There is intentionally no destructive "reset" endpoint.

## Security checklist

- [ ] Set a strong, unique `JWT_SECRET_KEY`.
- [ ] Set `APP_ENV=production`; verify the seeded-account endpoint and `/api/docs` are unavailable.
- [ ] Turn off both seeding flags in any environment that must not display initial-corpus records.
- [ ] Rotate the seeded operator passwords before the first sign-in.
- [ ] Serve only over HTTPS; HSTS at the proxy, and `DEEPSEEK_BASE_URL` on https.
- [ ] Restrict `CORS_ORIGINS` to the deployed origin.
- [ ] Keep connector keys and `DEEPSEEK_API_KEY` in a secret manager or environment, never in the repository.
- [ ] Back up the database and test restoration.
- [ ] Review the audit trail and active administrator count after handover.
- [ ] Keep the process user unprivileged and the filesystem read-only where possible.
- [ ] If email is enabled, verify SMTP TLS and sender authentication.

## Known operational limits

- No background scheduler: sync, detection and classifier evaluation runs are operator-triggered.
- No automatic containment or infrastructure changes by design.
- SQLite is not suitable for multiple writers under load.
- Aegis AI depends on provider availability, latency and quota. The platform sends only the bounded context retrieved for that turn, and a provider failure is recorded as a failed turn rather than a fabricated answer.
- Connector integrations depend on upstream availability and rate limits; failures are surfaced, not hidden.
