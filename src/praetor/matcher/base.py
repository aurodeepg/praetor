"""The capability-matcher contract and its result types.

The matcher is Phase 1's single, deliberately-cheap "AI seed": it turns a free-form
requirement into ranked candidate capabilities and a *proposed* least-privilege scope
for a human (or, later, the orchestrator) to approve. It only ever proposes — issuing
authority stays an explicit gateway action.
"""

from __future__ import annotations

import abc

from pydantic import BaseModel, Field

from praetor.models import Capability


class ScopeProposal(BaseModel):
    """A least-privilege scope the matcher proposes for approval."""

    agent: str
    capability: str
    scope: dict[str, str] = Field(default_factory=dict)
    excludes: list[str] = Field(default_factory=list)
    ttl: int = 300
    rationale: str = ""


class RankedCapability(BaseModel):
    agent: str
    capability: Capability
    score: float


class MatchResult(BaseModel):
    requirement: str
    ranked: list[RankedCapability] = Field(default_factory=list)
    proposal: ScopeProposal | None = None
    backend: str = "deterministic"

    @property
    def best(self) -> RankedCapability | None:
        return self.ranked[0] if self.ranked else None


class CapabilityMatcher(abc.ABC):
    """Maps a free-form requirement to registered capabilities + a scope proposal."""

    name: str = "matcher"

    @abc.abstractmethod
    def match(
        self,
        requirement: str,
        capabilities: list[tuple[str, Capability]],
        *,
        on_behalf_of: str = "",
    ) -> MatchResult:
        """Rank ``(agent, capability)`` pairs and propose a least-privilege scope."""
