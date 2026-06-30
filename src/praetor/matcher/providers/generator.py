"""Generation providers — the optional *scope-proposal* half of the semantic matcher.

Same provider-neutral story as embedders: `ollama` (local) and `openai` (any
OpenAI-compatible `/v1/chat/completions`, base_url-configurable). A generator only ever
*proposes* a structured scope; the matcher validates and falls back to deterministic
extraction if generation is unavailable or malformed — so this never weakens the
gateway. Constrained/JSON output is requested where the backend supports it.
"""

from __future__ import annotations

import abc
import os
from typing import Any

from praetor.matcher.providers.embedder import _httpx


class Generator(abc.ABC):
    name: str = "generator"

    @abc.abstractmethod
    def generate(self, prompt: str, *, schema: dict | None = None,
                 temperature: float = 0.0) -> str:
        ...

    def available(self) -> bool:
        return True


class OllamaGenerator(Generator):
    """Local generation via an Ollama daemon (`POST /api/generate`, temp 0 by default)."""

    def __init__(
        self, model: str, *, host: str | None = None, timeout: float = 60.0,
        client: Any | None = None,
    ) -> None:
        self.model = model
        self.host = (host or os.environ.get("PRAETOR_OLLAMA_HOST",
                                            "http://localhost:11434")).rstrip("/")
        self.name = f"ollama:{model}"
        self._timeout = timeout
        self._client = client

    def _http(self) -> Any:
        if self._client is None:
            self._client = _httpx().Client(timeout=self._timeout)
        return self._client

    def available(self) -> bool:
        try:
            return self._http().get(f"{self.host}/api/tags").status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def generate(self, prompt: str, *, schema: dict | None = None,
                 temperature: float = 0.0) -> str:
        body: dict[str, Any] = {
            "model": self.model, "prompt": prompt, "stream": False,
            "options": {"temperature": temperature},
        }
        if schema is not None:
            body["format"] = schema  # Ollama supports a JSON schema for constrained output
        resp = self._http().post(f"{self.host}/api/generate", json=body)
        resp.raise_for_status()
        return resp.json().get("response", "")


class OpenAICompatGenerator(Generator):
    """Generation via any OpenAI-compatible `/v1/chat/completions` endpoint."""

    def __init__(
        self, model: str, *, base_url: str | None = None, api_key: str | None = None,
        timeout: float = 60.0, client: Any | None = None,
    ) -> None:
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL",
                                                    "https://api.openai.com/v1")).rstrip("/")
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.name = f"openai:{model}"
        self._timeout = timeout
        self._client = client

    def _http(self) -> Any:
        if self._client is None:
            self._client = _httpx().Client(timeout=self._timeout)
        return self._client

    def available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str, *, schema: dict | None = None,
                 temperature: float = 0.0) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if schema is not None:
            body["response_format"] = {"type": "json_object"}  # widely-supported JSON mode
        resp = self._http().post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json=body,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
