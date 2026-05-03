"""Module 3 — LLM agent for attack path analysis.

Orchestrates batched analysis with retry, schema validation, and caching.
"""

import hashlib
import json
import logging
from pathlib import Path

from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.core.exceptions import LLMProviderError
from app.modules.llm_providers.base import LLMProvider
from app.modules.paths import AttackPathData
from app.schemas.path import PathAnalysisSchema

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent.parent / "data" / "prompts" / "analyze_path.txt"
_SUMMARY_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "data" / "prompts" / "executive_summary.txt"
)

_in_memory_cache: dict[str, dict] = {}


_llm_config_cache: dict | None = None
_llm_config_cache_ts: float = 0.0
_LLM_CACHE_TTL = 30.0


async def _load_db_llm_config() -> dict:
    """Load LLM config overrides from app_settings table (cached 30s)."""
    import time

    global _llm_config_cache, _llm_config_cache_ts
    now = time.monotonic()
    if _llm_config_cache is not None and (now - _llm_config_cache_ts) < _LLM_CACHE_TTL:
        return _llm_config_cache

    try:
        from sqlalchemy import or_, select

        from app.database import get_session_factory
        from app.models.setting import AppSetting

        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                select(AppSetting).where(
                    or_(
                        AppSetting.key.in_(["llm_provider", "llm_model"]),
                        AppSetting.key.like("llm_api_key%"),
                    )
                )
            )
            rows = result.scalars().all()
        raw = {r.key: r.value for r in rows if r.value}
        provider = raw.get("llm_provider", "")
        config = {
            "llm_provider": provider,
            "llm_model": raw.get("llm_model", ""),
            # per-provider key takes priority; fall back to legacy generic key
            "llm_api_key": raw.get(f"llm_api_key_{provider}", "") or raw.get("llm_api_key", ""),
        }
        _llm_config_cache = config
        _llm_config_cache_ts = now
        return config
    except Exception as exc:
        logger.debug("db_llm_config_unavailable", extra={"error": str(exc)})
        return {}


def invalidate_llm_cache() -> None:
    """Force next call to reload LLM config from DB."""
    global _llm_config_cache, _llm_config_cache_ts
    _llm_config_cache = None
    _llm_config_cache_ts = 0.0


async def _get_provider() -> LLMProvider:
    settings = get_settings()
    db_config = await _load_db_llm_config()

    provider_name = db_config.get("llm_provider") or settings.llm_provider
    api_key = db_config.get("llm_api_key", "")
    model = db_config.get("llm_model", "")

    if provider_name == "mock":
        from app.modules.llm_providers.mock_provider import MockProvider
        return MockProvider()
    elif provider_name == "anthropic":
        from app.modules.llm_providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=api_key, model=model)
    elif provider_name == "openai":
        from app.modules.llm_providers.openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=api_key, model=model)
    elif provider_name == "azure":
        from app.modules.llm_providers.azure_provider import AzureOpenAIProvider
        return AzureOpenAIProvider()
    elif provider_name == "ollama":
        from app.modules.llm_providers.ollama_provider import OllamaProvider
        return OllamaProvider(model=model)
    elif provider_name == "google":
        from app.modules.llm_providers.google_provider import GoogleProvider
        return GoogleProvider(api_key=api_key, model=model)
    elif provider_name == "openrouter":
        from app.modules.llm_providers.openrouter_provider import OpenRouterProvider
        return OpenRouterProvider(api_key=api_key, model=model)
    elif provider_name == "mistral":
        from app.modules.llm_providers.mistral_provider import MistralProvider
        return MistralProvider(api_key=api_key, model=model)
    else:
        raise LLMProviderError(f"Unknown provider: {provider_name}", provider=provider_name)


def _build_path_prompt(path: AttackPathData) -> str:
    template = _PROMPT_PATH.read_text(encoding="utf-8")

    mitre_lines = "\n".join(
        f"- {t['id']}: {t['name']} ({t['tactic']})" for t in path.mitre_techniques
    ) or "Aucune technique MITRE détectée"

    hop_lines = "\n".join(
        f"  {i + 1}. {h['source_label']} ({h['source_type']}) "
        f"--[{h['edge_type']}]--> {h['target_label']} ({h['target_type']})"
        for i, h in enumerate(path.hops)
    )

    return template.format(
        source_node=path.source_node,
        source_type=path.source_type,
        target_node=path.target_node,
        target_type=path.target_type,
        path_length=path.length,
        path_details=hop_lines,
        mitre_techniques=mitre_lines,
    )


def _cache_key(path: AttackPathData) -> str:
    return hashlib.sha256(path.canonical_key.encode()).hexdigest()


def _normalize_risk_level(risk: str) -> str:
    mapping = {
        "faible": "faible",
        "moyen": "moyen",
        "élevé": "eleve",
        "eleve": "eleve",
        "critique": "critique",
    }
    return mapping.get(risk.lower(), "moyen")


async def _analyze_single_path(path: AttackPathData, provider: LLMProvider, attempt: int = 0) -> dict:
    """Analyze one path with retry logic and schema validation."""
    cache_key = _cache_key(path)
    if cache_key in _in_memory_cache:
        logger.debug("cache_hit", extra={"path": path.source_node[:30]})
        return _in_memory_cache[cache_key]

    settings = get_settings()
    max_retries = settings.llm_max_retries
    last_error = None

    for attempt_num in range(max_retries):
        try:
            prompt = _build_path_prompt(path)
            raw = await provider.invoke(prompt)

            raw_stripped = raw.strip()
            if raw_stripped.startswith("```"):
                lines = raw_stripped.split("\n")
                raw_stripped = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

            parsed = json.loads(raw_stripped)
            validated = PathAnalysisSchema.model_validate(parsed)

            result = {
                "source_node": path.source_node,
                "target_node": path.target_node,
                "hops": path.hops,
                "length": path.length,
                "exploitability_score": float(validated.exploitability_score),
                "stealth_score": float(validated.stealth_score),
                "global_score": float(validated.global_score),
                "risk_level": _normalize_risk_level(validated.risk_level),
                "explanation_fr": validated.explanation,
                "recommendation_fr": validated.recommendation,
                "llm_raw_response": parsed,
                "mitre_techniques": [
                    {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "url": t["url"]}
                    for t in path.mitre_techniques
                ],
            }

            _in_memory_cache[cache_key] = result
            return result

        except (json.JSONDecodeError, ValueError, Exception) as exc:
            last_error = exc
            err_str = str(exc)
            logger.warning(
                "llm_parse_failed",
                extra={"attempt": attempt_num + 1, "error": err_str[:100]},
            )
            # 429 = quota/rate-limit — retrying immediately will never help; bail out.
            if "429" in err_str:
                logger.error("llm_rate_limited", extra={"provider": provider.provider_name})
                break

    logger.error("llm_all_retries_failed", extra={"path": path.source_node[:30]})
    return {
        "source_node": path.source_node,
        "target_node": path.target_node,
        "hops": path.hops,
        "length": path.length,
        "exploitability_score": None,
        "stealth_score": None,
        "global_score": None,
        "risk_level": "moyen",
        "explanation_fr": "analyse_echec — L'analyse automatisée a échoué après plusieurs tentatives.",
        "recommendation_fr": "Analyser manuellement ce chemin d'attaque.",
        "llm_raw_response": {"error": str(last_error)},
        "mitre_techniques": [
            {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "url": t["url"]}
            for t in path.mitre_techniques
        ],
    }


_HIGH_RISK_EDGES = frozenset({
    # Credential dumping / replication
    "GetChangesAll", "GetChanges", "GetChangesInFilteredSet", "DCSync",
    # Full object control
    "GenericAll", "WriteOwner", "WriteDACL", "Owns",
    # Account manipulation
    "ForceChangePassword", "GenericWrite", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "WriteAccountRestrictions",
    # Execution / lateral movement
    "AllowedToDelegate", "AllowedToAct", "HasSession", "AdminTo",
    "CanRDP", "CanPSRemote", "ExecuteDCOM",
    # Kerberos attacks
    "Kerberoastable", "ASREPRoastable",
    # ADCS certificate abuse
    "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
    "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    "GoldenCert", "ManageCA", "ManageCertificates",
    # Other high-value credential access
    "HasSIDHistory", "CoerceToTGT", "SyncLAPSPassword", "DumpSMSAPassword",
    "ReadLAPSPassword", "ReadGMSAPassword",
})

# Lower index = higher priority when selecting which paths get LLM analysis slots
_EDGE_PRIORITY = {e: i for i, e in enumerate([
    # Tier 0 — instant domain compromise
    "GetChangesAll", "GetChanges", "DCSync", "GoldenCert", "CoerceToTGT",
    # Tier 1 — full object control
    "GenericAll", "WriteOwner", "WriteDACL", "Owns",
    # Tier 2 — targeted control / shadow creds
    "ForceChangePassword", "GenericWrite", "AddKeyCredentialLink",
    "AllowedToDelegate", "AllowedToAct",
    # Tier 3 — kerberos credential attacks
    "Kerberoastable", "ASREPRoastable", "HasSession",
    "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword",
    # Tier 4 — ADCS
    "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
    "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    # Tier 5 — lateral movement
    "AdminTo", "AddMember", "CanRDP", "CanPSRemote", "ExecuteDCOM",
    # Tier 6 — structural (low priority for LLM slots)
    "MemberOf", "Contains", "TrustedBy",
])}


def _path_priority(path: "AttackPathData") -> tuple:
    """Lower tuple → higher priority. Sort key for path selection."""
    edge_types = {h.get("edge_type", "") for h in path.hops}
    min_edge_rank = min((_EDGE_PRIORITY.get(e, 99) for e in edge_types), default=99)
    return (path.length, min_edge_rank)


# Edges that by themselves make a path "critique" regardless of other factors
_INSTANT_CRITICAL = frozenset({
    "GetChangesAll", "GetChanges", "DCSync", "GoldenCert",
    "GenericAll", "CoerceToTGT",
    "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
    "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    "Kerberoastable", "ASREPRoastable",
})


def _heuristic_score(path: "AttackPathData") -> dict:
    """Fast rule-based scoring for paths that don't get an LLM analysis slot."""
    edge_types = {h.get("edge_type", "") for h in path.hops}
    high_risk_count = sum(1 for e in edge_types if e in _HIGH_RISK_EDGES)

    if edge_types & _INSTANT_CRITICAL:
        exploit, stealth, risk = 9.0, 4.0, "critique"
    elif high_risk_count >= 2 or "WriteOwner" in edge_types or "WriteDACL" in edge_types:
        exploit, stealth, risk = 8.0, 5.0, "eleve"
    elif high_risk_count == 1:
        exploit, stealth, risk = 7.0, 5.0, "eleve"
    elif path.length <= 2:
        exploit, stealth, risk = 6.0, 6.0, "moyen"
    else:
        exploit, stealth, risk = 4.0, 7.0, "moyen"

    global_score = round((exploit * 0.6 + (10 - stealth) * 0.4), 1)

    edges_str = " → ".join(sorted(edge_types))
    return {
        "source_node": path.source_node,
        "target_node": path.target_node,
        "hops": path.hops,
        "length": path.length,
        "exploitability_score": exploit,
        "stealth_score": stealth,
        "global_score": global_score,
        "risk_level": risk,
        "explanation_fr": f"Analyse heuristique (quota LLM atteint). Chemin de {path.length} saut(s) via {edges_str}.",
        "recommendation_fr": "Analyser manuellement ce chemin. Restreindre les droits délégués et vérifier les ACL.",
        "llm_raw_response": {"heuristic": True},
        "mitre_techniques": [
            {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "url": t["url"]}
            for t in path.mitre_techniques
        ],
    }


async def analyze_paths_batch(paths: list["AttackPathData"], analysis_id: str) -> list[dict]:
    """Analyze paths in batches using the configured LLM provider.

    Paths are sorted by risk priority. Only the top MAX_LLM_PATHS get real LLM
    analysis; the rest receive fast heuristic scoring so the pipeline stays
    responsive even on large domains.

    Args:
        paths: List of enriched attack paths.
        analysis_id: ID of the analysis (for logging).

    Returns:
        List of analysis result dicts (LLM + heuristic combined).
    """
    settings = get_settings()
    MAX_LLM_PATHS = getattr(settings, "llm_max_paths", 60)

    # Sort so the most dangerous / shortest paths get LLM slots first
    sorted_paths = sorted(paths, key=_path_priority)
    llm_paths = sorted_paths[:MAX_LLM_PATHS]
    heuristic_paths = sorted_paths[MAX_LLM_PATHS:]

    provider = await _get_provider()
    batch_size = settings.llm_batch_size
    results = []

    logger.info(
        "agent_batch_start",
        extra={
            "total_paths": len(paths),
            "llm_paths": len(llm_paths),
            "heuristic_paths": len(heuristic_paths),
            "batch_size": batch_size,
            "provider": provider.provider_name,
        },
    )

    for i in range(0, len(llm_paths), batch_size):
        batch = llm_paths[i : i + batch_size]
        for path in batch:
            result = await _analyze_single_path(path, provider)
            results.append(result)

        logger.info(
            "agent_batch_progress",
            extra={"processed": min(i + batch_size, len(llm_paths)), "total": len(llm_paths)},
        )
        # Respect free-tier rate limits (e.g. Gemini: 15 RPM, OpenRouter free).
        # Only pause between batches, not after the last one.
        if i + batch_size < len(llm_paths) and provider.provider_name not in ("mock",):
            import asyncio
            await asyncio.sleep(5)

    # Fast heuristic scoring for remaining paths (no LLM calls)
    for path in heuristic_paths:
        results.append(_heuristic_score(path))

    logger.info("agent_batch_done", extra={"results": len(results), "llm": len(llm_paths), "heuristic": len(heuristic_paths)})
    return results


async def generate_executive_summary(
    paths: list[dict],
    client_name: str,
    engagement_code: str,
    analysis_date: str,
) -> dict:
    """Generate an executive summary using the LLM.

    Args:
        paths: List of analyzed path dicts.
        client_name: Client organization name.
        engagement_code: Mission code.
        analysis_date: ISO date string.

    Returns:
        Executive summary dict.
    """
    from datetime import UTC, datetime

    provider = await _get_provider()
    settings = get_settings()

    counts = {"faible": 0, "moyen": 0, "eleve": 0, "critique": 0}
    scores = []
    for p in paths:
        rl = p.get("risk_level", "moyen")
        counts[rl] = counts.get(rl, 0) + 1
        if p.get("global_score") is not None:
            scores.append(p["global_score"])

    avg_score = sum(scores) / len(scores) if scores else 0
    mitre_ids: set[str] = set()
    for p in paths:
        for t in p.get("mitre_techniques", []):
            mitre_ids.add(t["id"])

    top_paths = sorted(
        [p for p in paths if p.get("global_score") is not None],
        key=lambda x: x["global_score"],
        reverse=True,
    )[:3]

    top_paths_text = "\n".join(
        f"{i+1}. {p['source_node']} → {p['target_node']} "
        f"(Score: {p['global_score']}, Niveau: {p['risk_level']})\n"
        f"   Explication: {(p.get('explanation_fr') or '')[:200]}..."
        for i, p in enumerate(top_paths)
    )

    template = _SUMMARY_PROMPT_PATH.read_text(encoding="utf-8")
    prompt = template.format(
        client_name=client_name,
        engagement_code=engagement_code,
        analysis_date=analysis_date,
        llm_provider=provider.provider_name,
        total_paths=len(paths),
        critical_count=counts.get("critique", 0),
        high_count=counts.get("eleve", 0),
        medium_count=counts.get("moyen", 0),
        low_count=counts.get("faible", 0),
        avg_score=round(avg_score, 1),
        mitre_count=len(mitre_ids),
        top_paths_details=top_paths_text,
    )

    settings = get_settings()
    for _ in range(settings.llm_max_retries):
        try:
            raw = await provider.invoke(prompt)
            raw_stripped = raw.strip()
            if raw_stripped.startswith("```"):
                lines = raw_stripped.split("\n")
                raw_stripped = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
            return json.loads(raw_stripped)
        except Exception as exc:
            logger.warning("summary_llm_failed", extra={"error": str(exc)[:100]})

    return {
        "verdict_global": "Élevé",
        "resume_executif": "Synthèse automatique indisponible — voir le détail des chemins.",
        "principaux_risques": ["Voir le rapport détaillé"],
        "recommandations_prioritaires": [
            {"priorite": 1, "action": "Consulter le détail des chemins critiques", "urgence": "Immédiate"}
        ],
        "feuille_de_route": "Prioriser la remédiation des chemins critiques identifiés.",
    }
