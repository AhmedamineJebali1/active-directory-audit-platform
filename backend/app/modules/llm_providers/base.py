"""Abstract LLM provider interface."""

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    """Base class for all LLM providers."""

    @abstractmethod
    async def invoke(self, prompt: str, system: str = "") -> str:
        """Send a prompt and return the raw text response.

        Args:
            prompt: The user message.
            system: Optional system prompt.

        Returns:
            Raw text response from the model.
        """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name."""
