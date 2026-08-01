"""Gemini adapter — govern a Google Gemini agent under a Praetor warrant.

Speaks Gemini's **native** Generative Language API
(``POST {base_url}/models/{model}:generateContent``) over plain HTTP, because its
request/response shape is genuinely different from Chat Completions:

* the system prompt is a top-level ``systemInstruction``, not a message role;
* messages are ``contents: [{role, parts: [{text}]}]``;
* the answer lives at ``candidates[0].content.parts[*].text``;
* auth is an ``x-goog-api-key`` header, not a bearer token.

Google *also* serves an OpenAI-compatible endpoint; if you prefer that path, point
:class:`~praetor.adapters.openai.OpenAIAdapter` at it instead — both are governed
identically, which is the whole point of the adapter layer.

Requires the ``llm`` extra (``httpx``) and an API key (``GEMINI_API_KEY`` or
``GOOGLE_API_KEY``).
"""

from __future__ import annotations

import os
from typing import Any

from praetor.adapters.llm import LLMAgentAdapter
from praetor.models import Capability

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


class GeminiAdapter(LLMAgentAdapter):
    """A Gemini agent as a governed Praetor agent.

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
        trust: str = "3rd-party · gemini · unverified",
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
            base_url or os.environ.get("GEMINI_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self._api_key = self._key(api_key, "GEMINI_API_KEY", "GOOGLE_API_KEY")
        self.backend = f"gemini:{model}"

    def _complete(self, system: str, prompt: str) -> str:
        if not self._api_key:
            raise RuntimeError("no API key — set GEMINI_API_KEY or pass api_key=")
        resp = self._http().post(
            f"{self.base_url}/models/{self.model}:generateContent",
            headers={"x-goog-api-key": self._api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0},
            },
        )
        resp.raise_for_status()
        return self._text(resp.json())

    @staticmethod
    def _text(payload: dict) -> str:
        """Join the text parts of the first candidate. A blocked or empty response
        (safety filter, no candidates) raises, so it surfaces as a failed ToolResult
        rather than a silently empty success."""
        candidates = payload.get("candidates") or []
        if not candidates:
            blocked = (payload.get("promptFeedback") or {}).get("blockReason")
            why = f" (blocked: {blocked})" if blocked else ""
            raise RuntimeError(f"no candidates returned{why}")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts)
