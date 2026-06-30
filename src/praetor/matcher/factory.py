"""Backend selection — turn config (specs / env) into a matcher, with safe fallback.

A spec is ``"<backend>:<model>"`` (the model keeps any further colons, e.g.
``ollama:qwen3-embedding:0.6b``). Backends: ``ollama`` (local) and ``openai`` (any
OpenAI-compatible endpoint). Selection is env-driven and **always degrades to the
deterministic matcher** when a backend is missing, unconfigured, or unreachable — so
the gateway works out of the box at $0 and never hard-fails on a model.

Env:
  PRAETOR_EMBEDDER   e.g. "ollama:qwen3-embedding:0.6b"   (enables the semantic matcher)
  PRAETOR_GENERATOR  e.g. "ollama:qwen3:0.6b"             (optional; richer scope proposals)
  PRAETOR_OLLAMA_HOST / OPENAI_BASE_URL / OPENAI_API_KEY  (backend connection details)
"""

from __future__ import annotations

import os

from praetor.matcher.base import CapabilityMatcher
from praetor.matcher.deterministic import DeterministicMatcher
from praetor.matcher.providers.embedder import Embedder, OllamaEmbedder, OpenAICompatEmbedder
from praetor.matcher.providers.generator import Generator, OllamaGenerator, OpenAICompatGenerator


def _split(spec: str) -> tuple[str, str]:
    backend, _, model = spec.partition(":")
    return backend.strip().lower(), model.strip()


def make_embedder(spec: str) -> Embedder | None:
    backend, model = _split(spec)
    if not model:
        return None
    if backend == "ollama":
        return OllamaEmbedder(model)
    if backend in ("openai", "openai-compat"):
        return OpenAICompatEmbedder(model)
    return None


def make_generator(spec: str) -> Generator | None:
    backend, model = _split(spec)
    if not model:
        return None
    if backend == "ollama":
        return OllamaGenerator(model)
    if backend in ("openai", "openai-compat"):
        return OpenAICompatGenerator(model)
    return None


def make_matcher(
    embedder_spec: str | None = None, generator_spec: str | None = None
) -> CapabilityMatcher:
    """The configured matcher, or the deterministic default. Reads ``PRAETOR_EMBEDDER`` /
    ``PRAETOR_GENERATOR`` when specs aren't passed explicitly. Any failure → deterministic."""
    embedder_spec = embedder_spec or os.environ.get("PRAETOR_EMBEDDER")
    generator_spec = generator_spec or os.environ.get("PRAETOR_GENERATOR")
    if not embedder_spec:
        return DeterministicMatcher()  # semantic ranking needs an embedder
    try:
        embedder = make_embedder(embedder_spec)
        if embedder is None or not embedder.available():
            return DeterministicMatcher()
        generator = None
        if generator_spec:
            g = make_generator(generator_spec)
            generator = g if (g is not None and g.available()) else None
        from praetor.matcher.semantic import SemanticMatcher
        return SemanticMatcher(embedder, generator=generator)
    except Exception:  # noqa: BLE001 - never let backend selection break the gateway
        return DeterministicMatcher()
