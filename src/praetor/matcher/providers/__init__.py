"""Model providers for the semantic matcher — provider-neutral embedders + generators.

Backends are reached over plain HTTP (`httpx`, lazy, behind the `[semantic]` extra):
`ollama` (local/offline) and `openai` (any OpenAI-compatible endpoint via base_url).
No provider SDKs, nothing privileged.
"""

from praetor.matcher.providers.embedder import (
    Embedder,
    OllamaEmbedder,
    OpenAICompatEmbedder,
)
from praetor.matcher.providers.generator import (
    Generator,
    OllamaGenerator,
    OpenAICompatGenerator,
)

__all__ = [
    "Embedder",
    "Generator",
    "OllamaEmbedder",
    "OllamaGenerator",
    "OpenAICompatEmbedder",
    "OpenAICompatGenerator",
]
