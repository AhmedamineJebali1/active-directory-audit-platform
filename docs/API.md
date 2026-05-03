# API Reference — AD Audit AI

Interactive documentation is also available at `https://localhost/docs` (Swagger UI) and `https://localhost/redoc` (ReDoc) when the stack is running.

All endpoints (except `/auth/login`, `/healthz`, `/readyz`) require a `Bearer` JWT in the `Authorization` header.

---

## Authentication

### `POST /api/v1/auth/login`

Authenticate and receive JWT tokens.

**Request body**
```json
{ "email": "admin@adauditai.local", "password": "ChangeMeNow!2026" }
```

**Response `200`**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer"
}
```

### `GET /api/v1/auth/me`

Returns the current authenticated user.

**Response `200`**
```json
{
  "id": "uuid",
  "email": "admin@adauditai.local",
  "full_name": "Administrateur",
  "role": "admin",
  "is_active": true
}
```

### `POST /api/v1/auth/register` *(admin only)*

Create a new user account.

---

## Engagements

### `GET /api/v1/engagements`

List engagements visible to the current user.

**Query params**: `limit` (default 20, max 100), `offset` (default 0)

### `POST /api/v1/engagements`

Create a new engagement (audit mission).

**Request body**
```json
{
  "client_name": "Acme Corp",
  "code": "DEL-2026-0001",
  "description": "Audit périmètre AD on-prem Q2 2026"
}
```

### `GET /api/v1/engagements/{id}`

Retrieve engagement details.

### `PATCH /api/v1/engagements/{id}`

Update engagement fields (status, description, etc.).

### `DELETE /api/v1/engagements/{id}`

Soft-delete an engagement (sets status to `archived`).

---

## Analyses

### `POST /api/v1/engagements/{id}/analyses`

Upload a BloodHound JSON and launch the analysis pipeline asynchronously.

**Request**: `multipart/form-data` with a `file` field containing a `.json` export.

**Response `202`** — Analysis object with `status: pending`.

The pipeline transitions: `pending → ingesting → extracting_paths → analyzing → completed` (or `failed`).

Subscribe to `/api/v1/ws/analyses/{id}` for real-time progress.

### `GET /api/v1/engagements/{id}/analyses`

List all analyses for an engagement.

### `GET /api/v1/analyses/{id}`

Retrieve an analysis (includes `status`, `progress`, `total_paths`).

### `GET /api/v1/analyses/{id}/paths`

List attack paths for a completed analysis.

**Query params**:
- `risk` — filter by risk level: `faible`, `moyen`, `eleve`, `critique`
- `min_score` — minimum global score (0–10)
- `technique` — filter by MITRE technique ID (e.g. `T1078`)
- `max_length` — maximum path hop count
- `limit` / `offset` — pagination

### `GET /api/v1/analyses/{id}/paths/{path_id}`

Full detail for a single attack path (includes hops, scores, explanation, MITRE techniques).

### `GET /api/v1/analyses/{id}/stats`

Aggregated statistics: risk level distribution, top techniques, average scores.

### `GET /api/v1/analyses/{id}/mitre`

MITRE ATT\&CK coverage map: techniques detected, count per tactic, top 10 techniques.

### `GET /api/v1/analyses/{id}/report.pdf`

Download the generated PDF report. Triggers generation if not yet cached.

---

## LDAP live collection (optional)

### `POST /api/v1/engagements/{id}/ldap-collect`

Trigger a live LDAP collection against an AD. **Requires explicit activation** — never enabled by default.

**Request body**
```json
{
  "ldap_server": "dc01.corp.local",
  "ldap_user": "CORP\\auditor",
  "ldap_password": "...",
  "base_dn": "DC=corp,DC=local"
}
```

---

## WebSocket

### `WS /api/v1/ws/analyses/{id}?token=<jwt>`

Real-time progress channel for an analysis.

**Server emits** JSON frames:
```json
{ "stage": "ingestion",  "progress": 5,   "message_fr": "Ingestion du graphe BloodHound en cours..." }
{ "stage": "extraction", "progress": 25,  "message_fr": "Extraction des chemins d'attaque..." }
{ "stage": "mitre",      "progress": 40,  "message_fr": "Enrichissement MITRE ATT&CK..." }
{ "stage": "analysis",   "progress": 55,  "message_fr": "Analyse par l'agent IA..." }
{ "stage": "persisting", "progress": 85,  "message_fr": "Sauvegarde des résultats..." }
{ "stage": "completed",  "progress": 100, "message_fr": "Analyse terminée avec succès !" }
{ "stage": "failed",     "progress": 0,   "message_fr": "Erreur : <detail>" }
```

Token is optional — authenticated connections receive the same events as unauthenticated ones. Malformed JWTs cause a close with code `4001`.

---

## Health checks

### `GET /healthz`

Returns `200 {"status": "ok"}` — liveness probe.

### `GET /readyz`

Returns `200` when PostgreSQL and Neo4j are reachable. Returns `503` otherwise — readiness probe.

---

## Error format

All errors follow:
```json
{ "detail": "<human-readable message>" }
```

| HTTP code | Meaning |
|-----------|---------|
| 400 | Validation error (invalid input) |
| 401 | Missing or expired JWT |
| 403 | Insufficient role |
| 404 | Resource not found |
| 422 | Unprocessable entity (Pydantic) |
| 500 | Internal server error |
