"""Ollama local LLM provider."""

import logging

import httpx

from app.config import get_settings
from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """Calls Ollama local API."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        self._base_url = settings.ollama_base_url
        self._model = model or settings.ollama_model
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature

    @property
    def provider_name(self) -> str:
        return "ollama"

    async def invoke(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": self._model,
                    "messages": messages,
                    "options": {"temperature": self._temperature, "num_predict": self._max_tokens},
                    "stream": False,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")
