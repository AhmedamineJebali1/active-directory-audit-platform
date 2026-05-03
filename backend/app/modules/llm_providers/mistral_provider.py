"""Mistral AI LLM provider via OpenAI-compatible API."""

import logging

from openai import AsyncOpenAI

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)

_MISTRAL_BASE_URL = "https://api.mistral.ai/v1"
_DEFAULT_MODEL = "mistral-small-latest"


class MistralProvider(LLMProvider):
    """Calls Mistral AI via its OpenAI-compatible endpoint."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        resolved_key = api_key or getattr(settings, "mistral_api_key", "")
        self._model = model or settings.llm_model or _DEFAULT_MODEL
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature
        self._client = AsyncOpenAI(api_key=resolved_key, base_url=_MISTRAL_BASE_URL)

    @property
    def provider_name(self) -> str:
        return "mistral"

    async def invoke(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        return response.choices[0].message.content or ""
