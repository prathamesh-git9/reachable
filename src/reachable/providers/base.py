"""Provider contracts isolate model access from reachability decisions.

The scanner can ask a language model to explain a finding, but the provider
interface deliberately only returns text. It has no way to change the static
analysis verdict, which keeps model failures from becoming security decisions.
"""

from __future__ import annotations

from typing import Protocol


class ProviderError(Exception):
    """Base class for provider failures."""


class TransientProviderError(ProviderError):
    """Retryable provider failure such as a timeout, rate limit, or 5xx."""


class PermanentProviderError(ProviderError):
    """Non-retryable provider failure such as invalid input or credentials."""


class ChatProvider(Protocol):
    """Minimal chat completion interface used by the explanation layer."""

    name: str
    model: str

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int = 1024,
    ) -> str:
        """Return provider-generated text for the supplied prompt."""
