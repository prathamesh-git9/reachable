"""OpenAI provider loaded only when explicitly configured.

The fake provider is the default because reachability triage should run without
credentials. This module imports the OpenAI SDK lazily so installations that do
not request the llm extra can still use the scanner, CLI, and API.
"""

from __future__ import annotations

import os
from typing import Any

from .base import PermanentProviderError, TransientProviderError

DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    """Chat provider backed by the OpenAI Responses API."""

    def __init__(self, model: str | None = None) -> None:
        openai = _load_openai()
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is required for OpenAIProvider; install the "
                "llm extra and set the environment variable."
            )

        self.name = "openai"
        self.model = model or os.environ.get("OPENAI_MODEL") or DEFAULT_MODEL
        self._openai = openai
        self._client = openai.OpenAI(api_key=api_key)

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int = 1024,
    ) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
            )
            return _response_text(response)
        except (
            self._openai.RateLimitError,
            self._openai.APITimeoutError,
            self._openai.APIConnectionError,
        ) as exc:
            raise TransientProviderError(str(exc)) from exc
        except self._openai.APIStatusError as exc:
            if exc.status_code >= 500:
                raise TransientProviderError(str(exc)) from exc
            raise PermanentProviderError(str(exc)) from exc


def _load_openai() -> Any:
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "OpenAIProvider requires the openai package; install reachable with "
            "the llm extra."
        ) from exc
    return openai


def _response_text(response: Any) -> str:
    choices = getattr(response, "choices", None) or []
    if choices:
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None)
        if isinstance(content, str):
            return content
    return str(response)
