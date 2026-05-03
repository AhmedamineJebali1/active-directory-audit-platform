"""LLM provider configuration API — allows runtime provider switching via UI."""

import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.security import get_current_user, require_role
from app.database import get_db
from app.models.setting import AppSetting
from app.modules.llm_providers.openrouter_provider import FREE_MODELS

logger = logging.getLogger(__name__)
router = APIRouter(tags=["llm"])


def _friendly_auth_error(provider: str, raw_err: str) -> str:
    """Return a clean French sentence from a raw provider auth error."""
    import ast
    import re

    hints = {
        "anthropic":  "Vérifiez votre clé sur console.anthropic.com",
        "openai":     "Vérifiez votre clé sur platform.openai.com/api-keys",
        "mistral":    "Vérifiez votre clé sur console.mistral.ai/api-keys",
        "google":     "Vérifiez votre clé sur aistudio.google.com/apikey",
        "openrouter": "Vérifiez votre clé sur openrouter.ai/keys",
    }
    hint = hints.get(provider, "Vérifiez votre clé API")

    msg = ""
    # Providers return either JSON or Python-repr dicts in the error string
    m = re.search(r"\{.*\}", raw_err, re.DOTALL)
    if m:
        raw_dict = m.group()
        # Try ast first (handles Python single-quoted dicts)
        try:
            obj = ast.literal_eval(raw_dict)
            msg = (
                obj.get("error", {}).get("message")
                or obj.get("message")
                or ""
            )
        except Exception:
            pass

    if not msg:
        # Fallback: pull 'message': '...' with regex
        m2 = re.search(r"['\"]message['\"]\s*:\s*['\"]([^'\"]+)['\"]", raw_err)
        if m2:
            msg = m2.group(1)

    if msg:
        msg = msg[:90].rstrip(".,")
        return f"Clé API invalide — {msg}. {hint}."
    return f"Clé API refusée par le fournisseur. {hint}."

PROVIDER_META: dict[str, dict] = {
    "mistral": {
        "label": "Mistral AI",
        "description": "Mistral Small, Medium, Large — modèles performants et économiques",
        "requires_key": True,
        "models": ["mistral-small-latest", "mistral-medium-latest", "mistral-large-latest", "open-mistral-7b", "open-mixtral-8x7b"],
        "docs_url": "https://console.mistral.ai/api-keys",
    },
    "anthropic": {
        "label": "Anthropic Claude",
        "description": "Claude Sonnet, Opus, Haiku — modèles de référence pour l'analyse",
        "requires_key": True,
        "models": ["claude-sonnet-4-5", "claude-opus-4-5", "claude-haiku-4-5", "claude-3-5-sonnet-20241022"],
        "docs_url": "https://console.anthropic.com/",
    },
    "openai": {
        "label": "OpenAI",
        "description": "GPT-4o, GPT-4 Turbo et variantes",
        "requires_key": True,
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "docs_url": "https://platform.openai.com/api-keys",
    },
    "google": {
        "label": "Google Gemini",
        "description": "Gemini 2.0 Flash / 1.5 Pro via API Google AI Studio",
        "requires_key": True,
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash-exp"],
        "docs_url": "https://aistudio.google.com/apikey",
    },
    "openrouter": {
        "label": "OpenRouter",
        "description": "Accès unifié à des centaines de modèles open-source et propriétaires",
        "requires_key": True,
        "free_models": FREE_MODELS,
        "models": [m["id"] for m in FREE_MODELS],
        "docs_url": "https://openrouter.ai/keys",
    },
    "ollama": {
        "label": "Ollama",
        "description": "Inférence 100% locale — aucune donnée ne quitte l'infrastructure",
        "requires_key": False,
        "models": ["llama3.1:8b", "llama3.1:70b", "mistral:7b", "mixtral:8x7b", "phi3:mini"],
        "docs_url": "https://ollama.ai/",
    },
    "mock": {
        "label": "Mode démo",
        "description": "Réponses générées localement pour les démonstrations sans API",
        "requires_key": False,
        "models": ["mock"],
        "docs_url": "",
    },
    "azure": {
        "label": "Azure OpenAI",
        "description": "OpenAI hébergé sur Azure (nécessite un déploiement)",
        "requires_key": True,
        "models": [],
        "docs_url": "https://portal.azure.com/",
    },
}


class LLMConfigRequest(BaseModel):
    provider: str
    model: str = ""
    api_key: str = ""
    force: bool = False  # skip key validation and save anyway


class LLMConfigResponse(BaseModel):
    provider: str
    model: str
    has_api_key: bool
    configured_providers: list[str] = []
    updated_at: str | None = None


class TestConnectionResponse(BaseModel):
    success: bool
    message: str
    provider: str


async def _get_setting(db: AsyncSession, key: str) -> str | None:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    row = result.scalar_one_or_none()
    return row.value if row else None


async def _set_setting(db: AsyncSession, key: str, value: str) -> None:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    row = result.scalar_one_or_none()
    if row:
        row.value = value
        row.updated_at = datetime.now(UTC)
    else:
        db.add(AppSetting(key=key, value=value, updated_at=datetime.now(UTC)))
    await db.commit()


@router.get("/llm/providers")
async def list_providers(current_user=Depends(get_current_user)) -> dict[str, Any]:
    """Return metadata for all supported LLM providers."""
    return {"providers": PROVIDER_META}


def _api_key_db_key(provider: str) -> str:
    return f"llm_api_key_{provider}"


async def _get_configured_providers(db: AsyncSession) -> list[str]:
    """Return providers that have a stored AND validated key."""
    result = await db.execute(
        select(AppSetting).where(AppSetting.key.like("llm_api_key_validated_%"))
    )
    rows = result.scalars().all()
    return [r.key.removeprefix("llm_api_key_validated_") for r in rows if r.value == "true"]


@router.get("/llm/config", response_model=LLMConfigResponse)
async def get_llm_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    """Return the current active LLM configuration."""
    settings = get_settings()
    provider = await _get_setting(db, "llm_provider") or settings.llm_provider
    model = await _get_setting(db, "llm_model") or settings.llm_model
    api_key = await _get_setting(db, _api_key_db_key(provider)) or ""

    result = await db.execute(select(AppSetting).where(AppSetting.key == "llm_provider"))
    row = result.scalar_one_or_none()
    updated_at = row.updated_at.isoformat() if row else None

    configured = await _get_configured_providers(db)

    return LLMConfigResponse(
        provider=provider,
        model=model,
        has_api_key=bool(api_key),
        configured_providers=configured,
        updated_at=updated_at,
    )


def _build_provider(provider: str, api_key: str, model: str):
    """Instantiate a provider with the given credentials for validation."""
    try:
        if provider == "anthropic":
            from app.modules.llm_providers.anthropic_provider import AnthropicProvider
            return AnthropicProvider(api_key=api_key, model=model)
        if provider == "openai":
            from app.modules.llm_providers.openai_provider import OpenAIProvider
            return OpenAIProvider(api_key=api_key, model=model)
        if provider == "mistral":
            from app.modules.llm_providers.mistral_provider import MistralProvider
            return MistralProvider(api_key=api_key, model=model)
        if provider == "google":
            from app.modules.llm_providers.google_provider import GoogleProvider
            return GoogleProvider(api_key=api_key, model=model)
        if provider == "openrouter":
            from app.modules.llm_providers.openrouter_provider import OpenRouterProvider
            return OpenRouterProvider(api_key=api_key, model=model)
    except Exception:
        pass
    return None


@router.put("/llm/config", response_model=LLMConfigResponse)
async def update_llm_config(
    payload: LLMConfigRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Update the active LLM provider, model, and API key (admin only).
    API key is validated with a live test call before being saved.
    Keys are stored per-provider so switching providers keeps all saved keys.
    """
    from app.modules.agent import invalidate_llm_cache

    if payload.provider not in PROVIDER_META:
        from app.core.exceptions import ValidationError
        raise ValidationError(f"Fournisseur inconnu : {payload.provider}")

    # Validate new key before saving — skip if force=True
    if payload.api_key and PROVIDER_META[payload.provider].get("requires_key") and not payload.force:
        provider_instance = _build_provider(payload.provider, payload.api_key, payload.model)
        if provider_instance:
            try:
                await provider_instance.invoke("Reply with the single word OK.")
            except Exception as exc:
                err = str(exc)
                # 429 = quota exceeded (key is valid), 404 = model not found (key may be valid)
                # Only reject on clear authentication errors
                if any(code in err for code in ("401", "403", "Unauthorized", "Invalid API key", "authentication")):
                    from app.core.exceptions import ValidationError
                    raise ValidationError(
                        f"CLÉ_INVALIDE:{_friendly_auth_error(payload.provider, err)}"
                    )
                # Other errors (429, 404, timeout) — key may be valid, save it with a note
                logger.warning("llm_key_validation_non_auth_error", extra={"provider": payload.provider, "error": err[:100]})

    await _set_setting(db, "llm_provider", payload.provider)
    if payload.model:
        await _set_setting(db, "llm_model", payload.model)
    if payload.api_key:
        await _set_setting(db, _api_key_db_key(payload.provider), payload.api_key)
        # Mark this key as validated (passed live check above)
        await _set_setting(db, f"llm_api_key_validated_{payload.provider}", "true")

    invalidate_llm_cache()
    logger.info("llm_config_updated", extra={"provider": payload.provider, "model": payload.model})

    configured = await _get_configured_providers(db)
    api_key = await _get_setting(db, _api_key_db_key(payload.provider)) or ""

    return LLMConfigResponse(
        provider=payload.provider,
        model=payload.model or get_settings().llm_model,
        has_api_key=bool(api_key),
        configured_providers=configured,
        updated_at=datetime.now(UTC).isoformat(),
    )


@router.delete("/llm/key/{provider}", status_code=204)
async def delete_provider_key(
    provider: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(require_role("admin")),
):
    """Remove the stored API key and validated flag for a provider (admin only)."""
    from app.modules.agent import invalidate_llm_cache

    for key in (_api_key_db_key(provider), f"llm_api_key_validated_{provider}"):
        result = await db.execute(select(AppSetting).where(AppSetting.key == key))
        row = result.scalar_one_or_none()
        if row:
            await db.delete(row)
    await db.commit()
    invalidate_llm_cache()
    logger.info("llm_key_deleted", extra={"provider": provider})


@router.post("/llm/test", response_model=TestConnectionResponse)
async def test_llm_connection(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    """Test the current LLM provider by sending a short prompt."""
    from app.modules.agent import _get_provider

    try:
        provider = await _get_provider()
        response = await provider.invoke("Réponds uniquement par le mot 'OK'.")
        success = bool(response and len(response.strip()) > 0)
        return TestConnectionResponse(
            success=success,
            message="Connexion réussie" if success else "Réponse vide reçue",
            provider=provider.provider_name,
        )
    except Exception as exc:
        logger.warning("llm_test_failed", extra={"error": str(exc)[:200]})
        return TestConnectionResponse(
            success=False,
            message=f"Erreur : {str(exc)[:150]}",
            provider="unknown",
        )


@router.get("/stats/global")
async def get_global_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
) -> dict[str, Any]:
    """Return platform-wide statistics for the dashboard."""
    from collections import Counter

    from sqlalchemy import func

    from app.models.analysis import Analysis, AttackPath, PathMitreTechnique
    from app.models.engagement import Engagement

    # Engagement counts
    eng_result = await db.execute(select(func.count()).select_from(Engagement))
    total_engagements = eng_result.scalar() or 0

    # Analysis counts
    analysis_result = await db.execute(
        select(Analysis.status, func.count()).group_by(Analysis.status)
    )
    analysis_by_status = dict(analysis_result.all())
    total_analyses = sum(analysis_by_status.values())

    # Attack path counts + risk distribution
    paths_result = await db.execute(
        select(AttackPath.risk_level, func.count()).group_by(AttackPath.risk_level)
    )
    by_risk = dict(paths_result.all())
    total_paths = sum(by_risk.values())

    # Recent analyses (last 5)
    recent_result = await db.execute(
        select(Analysis)
        .order_by(Analysis.started_at.desc())
        .limit(5)
    )
    recent = recent_result.scalars().all()
    recent_analyses = [
        {
            "id": str(a.id),
            "status": a.status,
            "source_filename": a.source_filename,
            "started_at": a.started_at.isoformat() if a.started_at else None,
            "total_paths": a.total_paths,
        }
        for a in recent
    ]

    # Top MITRE techniques
    mitre_result = await db.execute(
        select(PathMitreTechnique.technique_id, func.count())
        .group_by(PathMitreTechnique.technique_id)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_mitre = [{"id": tid, "count": cnt} for tid, cnt in mitre_result.all()]

    # Active LLM provider
    settings = get_settings()
    provider_setting = await _get_setting(db, "llm_provider")
    active_provider = provider_setting or settings.llm_provider
    model_setting = await _get_setting(db, "llm_model")
    active_model = model_setting or settings.llm_model

    return {
        "total_engagements": total_engagements,
        "total_analyses": total_analyses,
        "total_paths": total_paths,
        "analyses_by_status": analysis_by_status,
        "by_risk_level": by_risk,
        "recent_analyses": recent_analyses,
        "top_mitre": top_mitre,
        "active_llm": {"provider": active_provider, "model": active_model},
    }
