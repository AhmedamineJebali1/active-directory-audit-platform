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

        # Mistral supports OpenAI-style response_format. Using "json_object"
        # forces strict JSON output, eliminating the random "I'd be happy to
        # help! Here's the JSON: {...}" responses that break our parser.
        # If the model rejects the param (older models), fall back to free-form.
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
            # Older models / unsupported endpoints: drop the param and retry once
            if "response_format" in err or "json_object" in err:
                logger.debug("mistral_no_json_mode_fallback", extra={"err": err[:80]})
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    max_tokens=self._max_tokens,
                    temperature=self._temperature,
                )
            else:
                raise
        return response.choices[0].message.content or ""
