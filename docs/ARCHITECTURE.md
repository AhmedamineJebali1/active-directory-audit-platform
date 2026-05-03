# Architecture — AD Audit AI

## Overview

AD Audit AI is a five-layer web platform. Each layer is containerised and communicates over a private Docker bridge network (`adaudit_net`).

```
Browser
  │  HTTPS (443)
  ▼
Caddy (reverse proxy)
  ├── /           → Frontend (Nginx serving static HTML/CSS/JS)
  └── /api/*      → Backend (FastAPI + Uvicorn)
       ├── PostgreSQL 16   (application state)
       └── Neo4j 5         (graph queries)
             │
             └── LLM provider (Anthropic / OpenAI / Azure / Ollama)
```

---

## Backend pipeline (core)

When a BloodHound JSON is uploaded, a `BackgroundTask` executes the five-module pipeline:

```
Upload JSON
    │
    ▼
Module 1 — ingestion.py
    Parse BH JSON (v4 + v5 schemas)
    Build NetworkX DiGraph
    Persist graph to Neo4j (namespace per analysis_id)
    │
    ▼
Module 2 — paths.py
    all_simple_paths(cutoff=6) → non-privileged → privileged nodes
    Deduplicate via canonical edge-tuple key
    Annotate with metadata (edge types, source/target type)
    │
    ▼
Module 3 — mitre.py
    Load mitre_mapping.json
    Map each edge type to MITRE ATT&CK techniques
    Deduplicate techniques across path hops
    │
    ▼
Module 4 — agent.py
    Batch paths (default 5)
    Format French analysis prompt with path context + MITRE techniques
    Call LLM provider (pluggable: Anthropic / OpenAI / Azure / Ollama)
    Validate JSON response (Pydantic schema, 3 retries)
    Cache by hash(canonical_key) → skip re-analysis of identical paths
    On final failure → mark path "analyse_echec"
    │
    ▼
Module 5 — report.py
    Render Jinja2 template → WeasyPrint → PDF bytes
    Sections: cover, exec summary, methodology, path table,
              path details, MITRE annex, compliance annex
```

Progress is broadcast to WebSocket subscribers at each stage transition.

---

## Data model

```
users ──< engagements ──< analyses ──< attack_paths ──< path_mitre_techniques
```

All IDs are UUID v4. All timestamps are stored as `TIMESTAMPTZ` (UTC). The `attack_paths.hops` column is JSONB on PostgreSQL, JSON on SQLite (tests).

---

## LLM provider abstraction

```
modules/llm_providers/
    base.py                 Abstract LLMProvider (invoke → str)
    anthropic_provider.py   Claude (default)
    openai_provider.py      GPT models
    azure_provider.py       Azure OpenAI deployment
    ollama_provider.py      Local inference (zero data egress)
    mock_provider.py        Deterministic mock for CI / unit tests
```

The active provider is selected via `LLM_PROVIDER` env var. The agent module calls `_get_provider()` which reads settings at call time — no singleton, fully swappable in tests via `monkeypatch`.

---

## Authentication & authorisation

- JWT (HS256) issued on login. Access token: 15 min. Refresh token: 7 days.
- Every protected endpoint injects `get_current_user` via FastAPI `Depends`.
- Role check via `require_role("admin", "manager", ...)` dependency.
- Role hierarchy: `admin > manager > auditor`.
- Audit log middleware records every authenticated mutating request (action, resource, IP, user).

---

## WebSocket progress channel

```
Client                          Server
  │  WS /api/v1/ws/analyses/{id}  │
  │ ─────────────────────────────► │  accept + register in ConnectionManager
  │                                │
  │ ◄── {stage, progress, msg_fr}  │  broadcast at each pipeline stage
  │ ◄── {stage: "completed", 100}  │
  │  close                         │
```

The `ConnectionManager` is a module-level singleton. Multiple clients can subscribe to the same `analysis_id`. Dead sockets are cleaned up on broadcast failure.

---

## Deployment topology

| Service   | Image               | Exposed port (host) |
|-----------|---------------------|---------------------|
| caddy     | custom (alpine)     | 80, 443             |
| frontend  | custom (nginx)      | internal only       |
| backend   | custom (python 3.11)| internal only       |
| postgres  | postgres:16-alpine  | internal only       |
| neo4j     | neo4j:5-community   | internal only       |

Health checks on all services. `depends_on: condition: service_healthy` ensures correct startup order.
