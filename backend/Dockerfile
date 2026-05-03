FROM python:3.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser

WORKDIR /app

# ---- deps stage ----
FROM base AS deps

COPY pyproject.toml .
RUN uv pip install --system -e ".[dev]" 2>/dev/null || uv pip install --system \
    fastapi>=0.115.0 \
    uvicorn[standard]>=0.30.0 \
    sqlalchemy>=2.0.0 \
    alembic>=1.13.0 \
    "psycopg[binary]>=3.2.0" \
    "pydantic[email]>=2.9.0" \
    pydantic-settings>=2.5.0 \
    email-validator>=2.2.0 \
    "python-jose[cryptography]>=3.3.0" \
    "passlib[bcrypt]>=1.7.4" \
    "bcrypt<4.1" \
    python-multipart>=0.0.12 \
    networkx>=3.3 \
    neo4j>=5.24.0 \
    langchain>=0.3.0 \
    langchain-anthropic>=0.3.0 \
    langchain-openai>=0.2.0 \
    langchain-community>=0.3.0 \
    anthropic>=0.40.0 \
    openai>=1.54.0 \
    weasyprint>=62.0 \
    jinja2>=3.1.0 \
    aiofiles>=24.1.0 \
    httpx>=0.27.0 \
    tenacity>=9.0.0 \
    structlog>=24.4.0 \
    "ldap3>=2.9.0" \
    "pycryptodome>=3.20.0" \
    pytest>=8.0 \
    pytest-asyncio>=0.23 \
    pytest-cov>=5.0 \
    faker>=26.0 \
    aiosqlite>=0.20

# ---- dev stage ----
FROM deps AS dev
COPY . .
USER appuser
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ---- prod stage ----
FROM deps AS prod
ARG CACHEBUST=1
COPY . .
RUN chown -R appuser:appuser /app
USER appuser
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
