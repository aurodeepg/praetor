"""Per-agent profile the orchestrator scores team-fit against.

The registry says what an agent *could* do; an `AgentProfile` carries the rest of what
the orchestrator needs to decide whether to *put it on the team right now*: how much we
trust it, what it costs, whether it's available, and how it's been performing.

Trust is a free-form label everywhere else in Praetor; here it also needs a number. A
deterministic default weight is derived from the label, overridable per agent.
"""

from __future__ import annotations

from pydantic import BaseModel


def default_trust_weight(trust: str) -> float:
    """Map a free-form trust label to a [0,1] weight, deterministically."""
    t = trust.lower()
    if "untrusted" in t:
        return 0.3
    if "3rd-party" in t or "third-party" in t or "prob" in t:
        return 0.4
    if "unverified" in t:
        return 0.5
    if "internal" in t:
        return 1.0
    return 0.6


class AgentProfile(BaseModel):
    """What the orchestrator knows about one agent beyond its capabilities."""

    agent: str
    trust: str = "unverified"
    trust_weight: float | None = None   # explicit override; else derived from `trust`
    cost: float = 0.0                    # relative cost per engagement; 0 = free
    available: bool = True
    performance: float = 1.0            # rolling success signal in [0,1]; degrades on failure

    def weight(self) -> float:
        if self.trust_weight is not None:
            return self.trust_weight
        return default_trust_weight(self.trust)
