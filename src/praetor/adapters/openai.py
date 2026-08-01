"""OpenAI / ChatGPT adapter — govern a ChatGPT-family agent under a Praetor warrant.

Speaks the OpenAI **Chat Completions** shape (``POST {base_url}/chat/completions``)
over plain HTTP. Because that shape is the ecosystem's de-facto lingua franca, this
one adapter also governs anything else that serves it — Azure-hosted OpenAI-compatible
gateways, vLLM / llama.cpp / LM Studio / Ollama's compat endpoint, OpenRouter, and
Google's Gemini compatibility endpoint — by pointing ``base_url`` elsewhere. Dedicated
adapters exist for providers whose native API is a genuinely different shape
(:mod:`praetor.adapters.gemini`, :mod:`praetor.adapters.anthropic`).

Requires the ``llm`` extra (``httpx``) and an API key (``OPENAI_API_KEY``).
"""

from __future__ import annotations

import os
from typing import Any

from praetor.adapters.llm import LLMAgentAdapter
from praetor.models import Capability

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIAdapter(LLMAgentAdapter):
    """A ChatGPT-family agent as a governed Praetor agent.

    ``model`` is required and never defaulted: pinning a model id in library code ages
    badly, and a silently-retired default would surface as a confusing runtime error.
    The caller names the model they actually intend to govern.
    """

    def __init__(
        self,
        name: str,
        capabilities: list[Capability],
        *,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        trust: str = "3rd-party · openai · unverified",
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
            base_url or os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self._api_key = self._key(api_key, "OPENAI_API_KEY")
        self.backend = f"openai:{model}"

    def _complete(self, system: str, prompt: str) -> str:
        if not self._api_key:
            raise RuntimeError("no API key — set OPENAI_API_KEY or pass api_key=")
        resp = self._http().post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"] or ""
