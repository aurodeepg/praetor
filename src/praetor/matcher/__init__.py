"""Capability matchers — Phase 1's cheap "AI seed".

M4 ships the ``deterministic`` backend ($0, offline, the default). Optional ``local``
SLM and ``claude`` backends slot in behind the same :class:`CapabilityMatcher`
contract in a later milestone without touching the gateway.
"""

from praetor.matcher.base import (
    CapabilityMatcher,
    MatchResult,
    RankedCapability,
    ScopeProposal,
)
from praetor.matcher.deterministic import DeterministicMatcher

__all__ = [
    "CapabilityMatcher",
    "DeterministicMatcher",
    "MatchResult",
    "RankedCapability",
    "ScopeProposal",
]
