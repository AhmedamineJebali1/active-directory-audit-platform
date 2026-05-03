"""Application configuration via pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_SECRET = "change-me-to-a-long-random-string-min-32-chars"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: Literal["development", "production"] = "development"
    app_secret_key: str = _DEFAULT_SECRET
    app_base_url: str = "http://localhost:8000"
    log_level: str = "INFO"
    audit_debug_data: bool = False

    # Database
    database_url: str = "postgresql+psycopg://adaudit:changeme@localhost:5432/adaudit"
    postgres_user: str = "adaudit"
    postgres_password: str = "changeme"
    postgres_db: str = "adaudit"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Auth
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # Seed admin
    seed_admin_email: str = "admin@adauditai.local"
    seed_admin_password: str = "ChangeMeNow!2026"
    seed_admin_name: str = "Administrateur"

    # LLM provider
    llm_provider: Literal["anthropic", "openai", "azure", "ollama", "mock", "google", "openrouter", "mistral"] = "anthropic"
    llm_model: str = "claude-sonnet-4-5"
    llm_temperature: float = 0.2
    llm_max_tokens: int = 2000
    llm_batch_size: int = 5
    llm_max_retries: int = 3
    llm_timeout_seconds: int = 60
    llm_max_paths: int = 60  # max paths per analysis that get real LLM calls; rest get heuristic scores

    # Anthropic
    anthropic_api_key: str = ""

    # OpenAI
    openai_api_key: str = ""

    # Google Gemini
    google_api_key: str = ""

    # OpenRouter
    openrouter_api_key: str = ""

    # Mistral
    mistral_api_key: str = ""

    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_deployment: str = ""
    azure_openai_api_version: str = "2024-08-01-preview"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    # Report
    report_footer_text: str = "CONFIDENTIEL — Document de travail"
    report_brand_name: str = "AD Audit AI"

    # Paths
    data_dir: str = "/data"

    @model_validator(mode="after")
    def _check_production_secrets(self) -> "Settings":
        if self.app_env == "production" and self.app_secret_key == _DEFAULT_SECRET:
            raise ValueError(
                "APP_SECRET_KEY must be changed from the default value in production"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
