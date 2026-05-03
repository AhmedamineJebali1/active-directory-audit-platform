# Deployment Guide — AD Audit AI

## Development (local)

### Prerequisites

- Docker ≥ 24 with Compose v2 (`docker compose` command)
- 4 GB RAM available for containers (Neo4j alone needs ~1 GB)

### Steps

```bash
git clone <repo-url> ad-audit-ai
cd ad-audit-ai
cp .env.example .env
# Edit .env — set at minimum: APP_SECRET_KEY, ANTHROPIC_API_KEY (or switch LLM_PROVIDER)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

The dev override mounts source directories and enables Uvicorn hot reload. The backend port `8000` is exposed on the host for direct API testing.

Visit `https://localhost` (Caddy issues a self-signed cert in dev — accept the browser warning).

### Running tests locally (without Docker)

```bash
cd backend
uv pip install -e ".[dev]"
LLM_PROVIDER=mock pytest tests -q
```

WeasyPrint requires system libraries. On Ubuntu/Debian:
```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
  libffi-dev libcairo2 shared-mime-info fonts-dejavu-core
```

---

## Production

### Environment variables

Copy `.env.example` and set every variable marked as required:

| Variable | Required | Notes |
|----------|----------|-------|
| `APP_SECRET_KEY` | **yes** | Min 32 random chars. Use `openssl rand -hex 32`. |
| `APP_ENV` | yes | Set to `production` |
| `POSTGRES_PASSWORD` | **yes** | Change from default |
| `NEO4J_PASSWORD` | **yes** | Change from default |
| `SEED_ADMIN_PASSWORD` | **yes** | Change from default; triggers a startup warning if left as-is |
| `ANTHROPIC_API_KEY` | if using Anthropic | |
| `LLM_PROVIDER` | yes | `anthropic`, `openai`, `azure`, or `ollama` |

### TLS / HTTPS

Caddy automatically provisions a Let's Encrypt certificate in production when `APP_BASE_URL` contains a real domain. Update `caddy/Caddyfile` to replace `localhost` with your FQDN:

```
your.domain.com {
    reverse_proxy /api/* backend:8000
    reverse_proxy frontend:80
}
```

Then run:
```bash
docker compose up -d
```

### Database migrations

Migrations run automatically at backend startup via the `lifespan` handler. To run manually:

```bash
docker compose exec backend alembic upgrade head
```

To generate a new migration after changing models:

```bash
docker compose exec backend alembic revision --autogenerate -m "description"
```

### Scaling

The backend is stateless (sessions are JWT-based). Scale horizontally by adding replicas behind Caddy:

```yaml
# docker-compose.override.yml
services:
  backend:
    deploy:
      replicas: 3
```

Neo4j Community is single-node only. For HA Neo4j you need Enterprise.

### Backups

**PostgreSQL**:
```bash
docker compose exec postgres pg_dump -U adaudit adaudit | gzip > backup_$(date +%F).sql.gz
```

**Neo4j**:
```bash
docker compose exec neo4j neo4j-admin database dump neo4j --to-stdout | gzip > neo4j_$(date +%F).gz
```

**App data volume** (generated PDFs, uploaded files):
```bash
docker run --rm -v ad-audit-ai_app_data:/data alpine tar czf - /data > appdata_$(date +%F).tar.gz
```

### Log management

The backend emits JSON-structured logs in `production` mode. Route them to your SIEM or log aggregator:

```bash
docker compose logs -f backend | your-log-shipper
```

---

## Upgrading

1. Pull the latest images / rebuild:
   ```bash
   git pull
   docker compose build --no-cache
   ```
2. Run migrations:
   ```bash
   docker compose run --rm backend alembic upgrade head
   ```
3. Restart services:
   ```bash
   docker compose up -d
   ```

---

## Choosing an LLM provider for sensitive engagements

When auditing a client whose data must not leave your infrastructure, use the **Ollama** provider:

```bash
# In .env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3.1:8b
```

Add an Ollama service to your `docker-compose.override.yml`:

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    volumes:
      - ollama_models:/root/.ollama
    networks:
      - adaudit_net

volumes:
  ollama_models:
```

Pull the model before first use:
```bash
docker compose exec ollama ollama pull llama3.1:8b
```

No AD data will be sent to any external API in this configuration.
