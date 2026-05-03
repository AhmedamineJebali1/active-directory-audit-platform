"""Azure OpenAI LLM provider."""

import logging

from openai import AsyncAzureOpenAI

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(LLMProvider):
    """Calls Azure OpenAI Chat Completions API."""

    def __init__(self) -> None:
        settings = get_settings()
        self._client = AsyncAzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
        self._deployment = settings.azure_openai_deployment
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature

    @property
    def provider_name(self) -> str:
        return "azure"

    async def invoke(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = await self._client.chat.completions.create(
            model=self._deployment,
            messages=messages,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        return response.choices[0].message.content or ""
