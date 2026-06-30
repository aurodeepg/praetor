"""Capability matchers — the gateway's "semantic" seed.

M4 ships the ``deterministic`` backend ($0, offline, the default). M10 adds the
``semantic`` backend (embedding cosine ranking + optional generated scope proposal),
selected via :func:`make_matcher` from env config, behind the same
:class:`CapabilityMatcher` contract — so the gateway never changes. Backends are
provider-neutral (local Ollama / any OpenAI-compatible endpoint) and degrade gracefully
to ``deterministic``.
"""

from praetor.matcher.base import (
    CapabilityMatcher,
    MatchResult,
    RankedCapability,
    ScopeProposal,
)
from praetor.matcher.deterministic import DeterministicMatcher
from praetor.matcher.factory import make_embedder, make_generator, make_matcher
from praetor.matcher.semantic import SemanticMatcher

__all__ = [
    "CapabilityMatcher",
    "DeterministicMatcher",
    "MatchResult",
    "RankedCapability",
    "ScopeProposal",
    "SemanticMatcher",
    "make_embedder",
    "make_generator",
    "make_matcher",
]
