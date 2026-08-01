"""Anthropic / Claude adapter — govern a Claude-family agent under a Praetor warrant.

Speaks the Anthropic **Messages API** (``POST {base_url}/messages``) over plain HTTP.
Its shape is the one genuinely non-OpenAI-compatible provider surface, so it gets its
own adapter rather than riding :class:`~praetor.adapters.openai.OpenAIAdapter`:

* auth is an ``x-api-key`` header plus a required ``anthropic-version``;
* the system prompt is a **top-level** ``system`` field, not a message role;
* ``max_tokens`` is required, not optional;
* the answer is a *list* of content blocks — text lives in the ``text``-typed ones;
* a response can come back with ``stop_reason == "refusal"`` and empty content.

Deliberately no ``anthropic`` SDK: Praetor treats every provider uniformly over REST
(the M10 decision), so no vendor is privileged and the core install stays light. Note
also that ``temperature`` is **not** sent — current Claude models reject sampling
parameters with a 400, unlike the OpenAI/Gemini adapters where temperature 0 is valid.

Requires the ``llm`` extra (``httpx``) and an API key (``ANTHROPIC_API_KEY``).
"""

from __future__ import annotations

import os
from typing import Any

from praetor.adapters.llm import LLMAgentAdapter
from praetor.models import Capability

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
#: Pinned API version — the Messages API requires this header on every request.
ANTHROPIC_VERSION = "2023-06-01"
#: Required by the API and never inferred from the model. Generous enough for the
#: single-action completions an authorized ToolCall produces.
DEFAULT_MAX_TOKENS = 4096


class AnthropicAdapter(LLMAgentAdapter):
    """A Claude-family agent as a governed Praetor agent.

    ``model`` is required and never defaulted — see :class:`OpenAIAdapter` for why.
    """

    def __init__(
        self,
        name: str,
        capabilities: list[Capability],
        *,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        trust: str = "3rd-party · anthropic · unverified",
        description: str = "",
        system: str | None = None,
        timeout: float = 60.0,
        client: Any | None = None,
    ) -> None:
        super().__init__(
            name,
            capabilities,
            model=model,
            trust=trust,
            description=description,
            system=system,
            timeout=timeout,
            client=client,
        )
        self.base_url = (
            base_url or os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self._api_key = self._key(api_key, "ANTHROPIC_API_KEY")
        self.max_tokens = max_tokens
        self.backend = f"anthropic:{model}"

    def _complete(self, system: str, prompt: str) -> str:
        if not self._api_key:
            raise RuntimeError("no API key — set ANTHROPIC_API_KEY or pass api_key=")
        resp = self._http().post(
            f"{self.base_url}/messages",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": self.max_tokens,      # required by the Messages API
                "system": system,                   # top-level, not a message role
                "messages": [{"role": "user", "content": prompt}],
                # No temperature/top_p: current Claude models reject sampling params.
            },
        )
        resp.raise_for_status()
        return self._text(resp.json())

    @staticmethod
    def _text(payload: dict) -> str:
        """Join the text blocks of a Messages response.

        A safety refusal returns HTTP 200 with ``stop_reason == "refusal"`` and empty
        content — surfaced as a failed ToolResult rather than a silently empty success,
        so the audit trail records that the agent produced nothing and why."""
        if payload.get("stop_reason") == "refusal":
            raise RuntimeError("provider declined the request (stop_reason=refusal)")
        blocks = payload.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not text:
            raise RuntimeError(
                f"no text content returned (stop_reason={payload.get('stop_reason')})"
            )
        return text
