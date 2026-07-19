"""xAI Grok provider using the OpenAI-compatible API surface.

xAI exposes chat APIs through the OpenAI SDK shape. The provider keeps the same
error taxonomy as OpenAIProvider so retry logic can be shared by callers.
"""

from __future__ import annotations

import os
from typing import Any

from .base import PermanentProviderError, TransientProviderError

DEFAULT_MODEL = "grok-4.5"
BASE_URL = "https://api.x.ai/v1"


class GrokProvider:
    """Chat provider backed by xAI through the OpenAI-compatible SDK."""

    def __init__(self, model: str | None = None) -> None:
        openai = _load_openai()
        api_key = os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
        if not api_key:
            raise RuntimeError(
                "XAI_API_KEY or GROK_API_KEY is required for GrokProvider; "
                "install the llm extra and set one environment variable."
            )

        self.name = "grok"
        # Verified present in xAI's model list on 2026-07-19. xAI retires model
        # ids aggressively and keeps no bare-major aliases, so a plausible id
        # like "grok-3" 404s at the first live call.
        self.model = model or os.environ.get("XAI_MODEL") or DEFAULT_MODEL
        self._openai = openai
        self._client = openai.OpenAI(api_key=api_key, base_url=BASE_URL)

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
            "GrokProvider requires the openai package; install reachable with "
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
