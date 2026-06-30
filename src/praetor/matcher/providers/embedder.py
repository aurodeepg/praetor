"""Embedding providers — the *ranking* half of the semantic matcher.

Provider-neutral: an `Embedder` turns text into a vector; the matcher ranks by cosine
similarity. Two backends ship — `ollama` (local, offline, the demo) and `openai`
(any OpenAI-*compatible* `/v1/embeddings`: OpenAI, Gemini's compat endpoint, local
servers, … via a configurable base_url). No provider SDK lock-in; everything is plain
HTTP through ``httpx``, imported lazily behind the ``[semantic]`` extra.
"""

from __future__ import annotations

import abc
import os
from typing import Any


class Embedder(abc.ABC):
    """Turn texts into vectors. ``available()`` lets the factory degrade gracefully to
    the deterministic matcher when a backend isn't reachable/configured."""

    name: str = "embedder"

    @abc.abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...

    def available(self) -> bool:
        return True


def _httpx() -> Any:
    try:
        import httpx
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "semantic backends need httpx — install: pip install 'praetor[semantic]'"
        ) from exc
    return httpx


class OllamaEmbedder(Embedder):
    """Local embeddings via an Ollama daemon (`POST /api/embeddings`)."""

    def __init__(
        self, model: str, *, host: str | None = None, timeout: float = 30.0,
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
        except Exception:  # noqa: BLE001 - daemon down/unreachable → fall back
            return False

    def embed(self, texts: list[str]) -> list[list[float]]:
        client = self._http()
        out: list[list[float]] = []
        for text in texts:
            resp = client.post(f"{self.host}/api/embeddings",
                               json={"model": self.model, "prompt": text})
            resp.raise_for_status()
            out.append(resp.json()["embedding"])
        return out


class OpenAICompatEmbedder(Embedder):
    """Embeddings via any OpenAI-compatible `/v1/embeddings` endpoint (base_url + key)."""

    def __init__(
        self, model: str, *, base_url: str | None = None, api_key: str | None = None,
        timeout: float = 30.0, client: Any | None = None,
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

    def embed(self, texts: list[str]) -> list[list[float]]:
        resp = self._http().post(
            f"{self.base_url}/embeddings",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self.model, "input": texts},
        )
        resp.raise_for_status()
        data = sorted(resp.json()["data"], key=lambda d: d.get("index", 0))
        return [d["embedding"] for d in data]
