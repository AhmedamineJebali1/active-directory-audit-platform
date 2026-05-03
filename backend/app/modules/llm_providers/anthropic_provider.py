"""Anthropic Claude LLM provider."""

import logging

import anthropic

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    """Calls Anthropic Claude API."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        resolved_key = api_key or settings.anthropic_api_key
        self._client = anthropic.AsyncAnthropic(api_key=resolved_key)
        self._model = model or settings.llm_model
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def invoke(self, prompt: str, system: str = "") -> str:
        settings = get_settings()
        messages = [{"role": "user", "content": prompt}]
        kwargs = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = await self._client.messages.create(**kwargs)
        return response.content[0].text
