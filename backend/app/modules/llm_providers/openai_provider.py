"""OpenAI LLM provider."""

import logging

from openai import AsyncOpenAI

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    """Calls OpenAI Chat Completions API."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        resolved_key = api_key or settings.openai_api_key
        self._client = AsyncOpenAI(api_key=resolved_key)
        self._model = model or settings.llm_model or "gpt-4o"
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature

    @property
    def provider_name(self) -> str:
        return "openai"

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
