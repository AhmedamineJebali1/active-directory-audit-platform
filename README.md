<div align="center">

# AD Audit AI

**Automated Active Directory Security Audit Platform**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

*Detect attack paths. Score with AI. Deliver audit-ready PDF reports.*

</div>

---

**AD Audit AI** is a multi-user platform that automates security audits of Active Directory environments. Upload a BloodHound JSON or ZIP export — or connect directly to a domain controller via LDAP — and the platform extracts every viable attack path toward privileged accounts, scores each with a pluggable LLM, maps every hop to MITRE ATT&CK, and produces a deliverable French-language PDF report.

> Built as a final-year engineering project (PFE). Designed for cyber-audit consulting teams.

---

## Features

| | |
|---|---|
| **Real BloodHound CE support** | Parses the actual SharpHound 2.x / BloodHound CE v6 ZIP format, BloodHound v5 JSON, BloodHound v4 sections format, and a simple custom format. Locale-independent — works on French / German / English domain controllers |
| **DCSync synthesized correctly** | A principal with both `GetChanges` and `GetChangesAll` on a Domain object emits a synthetic `DCSync` edge — matching BloodHound's own derivation |
| **Live LDAP collection** | Connects to a domain controller (LDAP or LDAPS), parses binary security descriptors for ACL edges, resolves `primaryGroupID`, `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `sIDHistory`, Kerberoastable, AS-REP roastable. SMB-only edges (AdminTo, HasSession, etc.) are clearly flagged as heuristic |
| **AI-powered scoring** | Pluggable LLM provider — Mistral, Gemini, OpenAI, Anthropic, OpenRouter, Ollama. Strict JSON output enforced via `response_format`. Heuristic fallback when the LLM is unavailable, so the platform never produces empty results |
| **MITRE ATT&CK matrix** | Every BloodHound edge mapped to MITRE techniques. Engagement view shows a tactic × technique heatmap colored by detection count |
| **PDF report** | Multi-page styled report via WeasyPrint + Jinja2: cover, executive summary, path listings, MITRE annex, ISO 27001 / NIST CSF compliance mapping |
| **Multi-user with RBAC** | Three global roles (admin / manager / auditor) plus per-engagement membership (lead / contributor / viewer). Each auditor sees only the missions they're added to |
| **Audit log** | Every mutating request (POST/PATCH/PUT/DELETE) recorded with user, IP, route, latency, status. Admin viewer + filter UI |
| **Invite + reset flows** | Admin can invite users by email; users set their own password via single-use token. Forgot-password flow with rate-limiting and no email enumeration |
| **Real-time progress** | WebSocket-streamed pipeline stages with HTTP polling fallback |
| **100% local mode** | Ollama provider keeps AD data on-premise — nothing sent to external APIs |

---

## Quick Start

### Prerequisites

- **Docker** ≥ 24 and **Docker Compose v2** (run `docker compose version` to check)
- A free TCP port **443** (or change it in `docker-compose.yml` if it conflicts)
- ~2 GB free disk space (Postgres + Neo4j + app images)
- Optional: an LLM API key (Mistral, Gemini, OpenAI, Anthropic, or OpenRouter). Without one, the platform runs in **mock** mode and shows simulated analyses

### One-command setup

```bash
# 1. Clone the repo
git clone https://github.com/AhmedamineJebali1/active-directory-audit-platform.git
cd active-directory-audit-platform

# 2. Create your .env from the template
cp .env.example .env

# 3. Generate a secure secret key (run one of these and paste into .env as APP_SECRET_KEY)
#    Linux/macOS:
openssl rand -hex 32
#    Windows PowerShell:
#    [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

# 4. Edit .env — at minimum:
#    APP_SECRET_KEY=<paste output above>
#    SEED_ADMIN_PASSWORD=<your own password, ≥ 12 chars, mix of types>
#    POSTGRES_PASSWORD=<random>
#    NEO4J_PASSWORD=<random>

# 5. Launch
docker compose up -d --build

# 6. Wait ~30 s for the stack to come up, then check:
docker compose ps              # all services should be "running" / "healthy"
docker compose logs backend    # look for "db_schema_ready_alembic"

# 7. Open https://localhost in your browser
#    Self-signed cert in dev — accept the warning, or import caddy/data/caddy/pki/authorities/local/root.crt
```

### First login

Use the credentials you set in `.env`:

```
Email:    admin@adauditai.local   (or whatever SEED_ADMIN_EMAIL is set to)
Password: <your SEED_ADMIN_PASSWORD>
```

The first user is always an admin. Use **Utilisateurs** in the sidebar to invite teammates.

### Development mode (hot reload)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This mounts the backend source as a volume and runs `uvicorn --reload`. Frontend changes require rebuilding the frontend container (nginx serves static files).

### Troubleshooting

| Symptom | Fix |
|---|---|
| Browser can't reach `https://localhost` | `docker compose ps` — is `caddy` running on `0.0.0.0:443→443`? If another process owns 443, free it or change the binding |
| "Configuration de production invalide" in logs | `APP_ENV=production` requires non-default `APP_SECRET_KEY`, `SEED_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`. Either set them or use `APP_ENV=development` |
| Login returns 500 | Migrations didn't apply. Run `docker compose exec backend alembic upgrade head`, then restart backend |
| "Session expirée" right after login | You probably typed a wrong password or hit the 5-attempts-per-5-min lockout. Wait 15 min or `docker compose restart backend` to clear the in-memory bucket |
| Analyses always say `llm=mock` | Go to **Configuration LLM** in the sidebar (admin only), pick your provider, paste the API key, and click "Tester la connexion" |
| Upload says "Aucun chemin d'attaque trouvé" | This is correct when the ingested graph has no path from a non-privileged user to a privileged group. Try a larger BloodHound export — small lab domains often have no exploitable path |

### Deploying to a real domain

1. Set `APP_ENV=production` in `.env`
2. Set `PUBLIC_DOMAIN=adaudit.your-domain.com`
3. Point that DNS record at the host
4. Open ports **80** and **443** to the world
5. `docker compose up -d --build`

Caddy auto-issues a Let's Encrypt cert. HSTS is on automatically in production.

---

## LLM Provider Setup

Pick any of the supported providers. You can also change it later via **Configuration LLM** in the sidebar (admin only) — the in-app config overrides `.env`.

| Provider | Models | API key URL |
|---|---|---|
| **Mistral** | `mistral-small-latest`, `mistral-large-latest` | https://console.mistral.ai/api-keys |
| **Google Gemini** | `gemini-2.0-flash`, `gemini-1.5-pro` | https://aistudio.google.com/apikey |
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo` | https://platform.openai.com/api-keys |
| **Anthropic** | `claude-sonnet-4-5`, `claude-opus-4-5` | https://console.anthropic.com |
| **OpenRouter** | Many models including free-tier Llama, Gemma, Mistral | https://openrouter.ai/keys |
| **Ollama** | Local — `llama3.1:8b`, `mistral:7b`, etc. | No key — run `ollama serve` on the host |
| **mock** | Deterministic simulated output — for testing only |

The platform sends `response_format={"type":"json_object"}` to every provider that supports it. If the model rejects the parameter, it transparently retries without it.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser (Auditor)                      │
│           Alpine.js  ·  Chart.js  ·  Cytoscape.js          │
└─────────────────────────┬────────────────────────────────┘
                          │  HTTPS / WebSocket
                  ┌───────▼────────┐
                  │     Caddy      │  Reverse proxy + Auto-TLS
                  └───────┬────────┘
                          │
            ┌─────────────▼──────────────────┐
            │         FastAPI Backend          │
            │                                 │
            │  ┌───────────────────────────┐  │
            │  │      Pipeline Modules      │  │
            │  │  ingestion → paths         │  │
            │  │  → mitre → agent → report  │  │
            │  └──────────────┬────────────┘  │
            │                 │               │
            │   ┌─────────────▼───────────┐   │
            │   │      LLM Providers       │   │
            │   │  Mistral  · Gemini       │   │
            │   │  OpenAI · Anthropic      │   │
            │   │  OpenRouter · Ollama     │   │
            │   └─────────────────────────┘   │
            └────────┬────────────┬───────────┘
                     │            │
          ┌──────────▼──┐   ┌─────▼──────┐
          │ PostgreSQL  │   │   Neo4j    │
          │ (app + logs)│   │  (graph)   │
          └─────────────┘   └────────────┘
```

---

## Workflow

1. **Login** at `https://localhost` (or your `PUBLIC_DOMAIN`)
2. **Create an engagement** (admin or manager) with client name + mission code
3. **Upload a BloodHound JSON / ZIP**, drag-and-drop or click. Or use the live LDAP collector
4. Watch the **progress bar** update via WebSocket through ingestion → path extraction → MITRE enrichment → AI analysis
5. Browse:
   - **Analyse** — pipeline status + actions
   - **Graphe AD** — interactive Cytoscape graph
   - **Chemins d'attaque** — sortable table with risk + score filters
   - **Matrice MITRE** — tactic × technique heatmap
6. Click any path for the detail view: SVG mini-graph, MITRE techniques, AI explanation, embedded remediation playbook, prev/next navigation through related paths
7. **Download** the PDF report or the per-path remediation ZIP bundle
8. **Invite teammates** via the Utilisateurs page (admin only)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI 0.115+, Uvicorn, WebSocket |
| Databases | PostgreSQL 16 (application data), Neo4j 5 Community (graph) |
| ORM / Migrations | SQLAlchemy 2, Alembic (auto-applied on startup) |
| Graph analysis | NetworkX 3, BFS with wall-clock budget per source-target pair |
| LLM orchestration | Custom multi-provider abstraction with JSON-mode enforcement |
| Validation | Pydantic v2 |
| PDF generation | WeasyPrint 62, Jinja2 3 |
| Authentication | python-jose (JWT), passlib + bcrypt, token-version revocation |
| Frontend | HTML5, CSS3, Alpine.js 3, Chart.js 4, Cytoscape.js 3 — zero build step |
| Reverse proxy | Caddy 2 (automatic HTTPS via Let's Encrypt in production) |
| Containerization | Docker, Docker Compose v2 |
| Testing | pytest, pytest-asyncio, httpx |

---

## Project Structure

```
ad-audit-ai/
├── backend/
│   ├── app/
│   │   ├── api/v1/                       # REST endpoints
│   │   │   ├── auth.py                       # /login, /refresh, /logout, /invite, /reset
│   │   │   ├── engagements.py                # Mission CRUD + member management
│   │   │   ├── analyses.py                   # Upload, pipeline, /detect-format preview
│   │   │   ├── paths.py                      # Attack paths with filters
│   │   │   ├── reports.py                    # PDF download
│   │   │   ├── stats.py / mitre.py           # Stats + MITRE coverage
│   │   │   ├── ldap_collector.py             # Live LDAP collection
│   │   │   ├── llm_settings.py               # LLM provider config UI backend
│   │   │   ├── admin.py                      # Admin audit log + user management
│   │   │   └── ws.py                         # WebSocket real-time progress
│   │   ├── core/
│   │   │   ├── security.py                   # JWT + RBAC dependencies
│   │   │   ├── engagement_access.py          # Per-engagement membership gate
│   │   │   ├── audit.py                      # Audit log middleware
│   │   │   ├── rate_limit.py                 # Login bucket
│   │   │   ├── auth_tokens.py                # Invite + reset token issuance
│   │   │   ├── password_policy.py            # 12+ chars, 3-of-4 classes
│   │   │   └── notifications.py              # Email service (console + SMTP)
│   │   ├── models/                       # SQLAlchemy ORM
│   │   ├── schemas/                      # Pydantic v2 request/response
│   │   └── modules/
│   │       ├── ingestion.py                  # BloodHound JSON/ZIP → NetworkX
│   │       ├── paths.py                      # BFS path extraction with budget
│   │       ├── agent.py                      # LLM agent + heuristic fallback
│   │       ├── mitre.py                      # MITRE enrichment
│   │       ├── report.py                     # WeasyPrint PDF generation
│   │       ├── remediation.py                # Per-path mitigation playbook
│   │       ├── ldap_collector.py             # Binary SD parser + LDAP queries
│   │       └── llm_providers/                # Mistral, Gemini, OpenAI, Anthropic, OpenRouter, Ollama
│   ├── data/
│   │   ├── mitre_mapping.json                # 60+ edge types → MITRE techniques
│   │   ├── compliance_mapping.json           # MITRE → ISO 27001 / NIST CSF
│   │   └── sample_graph.json                 # Synthetic test export
│   ├── templates/                            # Jinja2 PDF template
│   ├── alembic/versions/                     # 0001–0006 schema migrations
│   └── tests/                                # Unit + integration tests
├── frontend/
│   ├── public/                               # HTML pages (Alpine.js, no build)
│   ├── js/                                   # Vanilla JS modules
│   ├── css/                                  # Tokens + components + toast
│   └── nginx.conf                            # Cache control + security headers
├── caddy/                                    # Caddyfile (PUBLIC_DOMAIN-driven)
├── docs/                                     # Architecture docs
├── docker-compose.yml                        # Production stack
└── docker-compose.dev.yml                    # Dev override (hot reload, exposed ports)
```

---

## API Reference

Swagger UI: `https://localhost/api/docs`

```
# Auth
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
POST   /api/v1/auth/invite              (admin)
POST   /api/v1/auth/accept-invite
POST   /api/v1/auth/forgot-password
POST   /api/v1/auth/reset-password

# Engagements + members
GET    /api/v1/engagements
POST   /api/v1/engagements              (admin/manager)
PATCH  /api/v1/engagements/{id}         (lead-on-engagement or admin)
GET    /api/v1/engagements/{id}/members
POST   /api/v1/engagements/{id}/members
DELETE /api/v1/engagements/{id}/members/{user_id}

# Analyses
POST   /api/v1/analyses/detect-format         # Preview before full pipeline
POST   /api/v1/engagements/{id}/analyses      # Upload → launch pipeline
POST   /api/v1/engagements/{id}/ldap-collect  # Live LDAP collection
GET    /api/v1/analyses/{id}                  # Status
GET    /api/v1/analyses/{id}/events           # WS replay buffer + error_message
GET    /api/v1/analyses/{id}/graph            # Cytoscape data
GET    /api/v1/analyses/{id}/paths            # ?risk=critique&min_score=7
GET    /api/v1/analyses/{id}/mitre            # Coverage map
GET    /api/v1/analyses/{id}/stats
GET    /api/v1/analyses/{id}/report.pdf

# Remediation
GET    /api/v1/analyses/{id}/paths/{path_id}/remediation-script   # Markdown
GET    /api/v1/analyses/{id}/remediation-bundle.zip               # All paths zipped

# Admin
GET    /api/v1/admin/audit-logs               (admin)
GET    /api/v1/admin/users                    (admin)
PATCH  /api/v1/admin/users/{id}               (admin)
POST   /api/v1/admin/users/{id}/disable       (admin)
POST   /api/v1/admin/users/{id}/enable        (admin)
POST   /api/v1/auth/admin/users/{id}/force-logout (admin)

# LLM
GET    /api/v1/llm/providers
GET    /api/v1/llm/config
PUT    /api/v1/llm/config                     (admin)
POST   /api/v1/llm/test                       (admin)

# WebSocket
WS     /ws/analyses/{id}                      # Real-time pipeline events
```

---

## Running Tests

```bash
# All tests
docker compose exec backend pytest -q

# Just the ingestion + paths logic (no DB required)
docker compose exec backend pytest tests/unit/test_ingestion.py tests/unit/test_paths.py -q
```

---

## Security & Ethics

This tool is **only** for security audits of Active Directory environments you own or have explicit written permission to test.

- All AD data stays on-premise when using the Ollama provider
- No AD identifiers logged at INFO level (`AUDIT_DEBUG_DATA=false` by default)
- Every mutating action recorded in the audit log
- JWT access tokens expire in 15 minutes; refresh tokens in 7 days
- Server-side session revocation via `users.token_version` — logout invalidates all sessions
- Login rate-limited per (email, IP); 15-minute lockout after 5 failed attempts
- Password policy: ≥ 12 chars, 3 of {upper, lower, digit, symbol}
- Defense-in-depth headers (HSTS in production, X-Frame-Options DENY, CSP, Permissions-Policy)
- Refuses to boot with default secrets in `production` mode

---

## License

[MIT](LICENSE)
