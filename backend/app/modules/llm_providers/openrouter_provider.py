"""OpenRouter LLM provider — access hundreds of models via a unified API."""

import logging

from openai import AsyncOpenAI

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)

_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_DEFAULT_MODEL = "meta-llama/llama-3.1-8b-instruct:free"

FREE_MODELS = [
    {"id": "meta-llama/llama-3.1-8b-instruct:free", "name": "Llama 3.1 8B (gratuit)"},
    {"id": "mistralai/mistral-7b-instruct:free", "name": "Mistral 7B (gratuit)"},
    {"id": "google/gemma-2-9b-it:free", "name": "Gemma 2 9B (gratuit)"},
    {"id": "microsoft/phi-3-mini-128k-instruct:free", "name": "Phi-3 Mini 128K (gratuit)"},
    {"id": "qwen/qwen-2-7b-instruct:free", "name": "Qwen 2 7B (gratuit)"},
]


class OpenRouterProvider(LLMProvider):
    """Calls OpenRouter API, which provides access to many open-source models."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        resolved_key = api_key or getattr(settings, "openrouter_api_key", "")
        self._model = model or settings.llm_model or _DEFAULT_MODEL
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature
        self._client = AsyncOpenAI(
            api_key=resolved_key,
            base_url=_OPENROUTER_BASE_URL,
            default_headers={
                "HTTP-Referer": "https://ad-audit-ai.local",
                "X-Title": "AD Audit AI",
            },
        )

    @property
    def provider_name(self) -> str:
        return "openrouter"

    async def invoke(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # OpenRouter routes to many backends; some support response_format,
        # some don't. Try once with json_object, fall back on rejection.
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                response_format={"type": "json_object"},
            )
        except Exception as exc:
            err = str(exc)
            if "response_format" in err or "json_object" in err:
                logger.debug("openrouter_no_json_mode_fallback", extra={"err": err[:80]})
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    max_tokens=self._max_tokens,
                    temperature=self._temperature,
                )
            else:
                raise
        return response.choices[0].message.content or ""
