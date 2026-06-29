"""The team-fit score — Phase 2's deterministic reasoning core.

The public vision states the formula literally: **fit = capability × trust × budget ×
availability**. We honour that as a product of four factors each normalised to [0,1], so
that any zero factor (no capability match, unavailable, priced out) zeroes the fit and
drops the agent from contention — exactly the intended gate behaviour.

The score is deterministic and pure (no inference here — that's an opt-in matcher
backend, M10). Every component is surfaced on :class:`FitScore` so a composition
decision is fully explainable in the audit trail.
"""

from __future__ import annotations

from pydantic import BaseModel

from praetor.orchestrator.profile import AgentProfile


class FitScore(BaseModel):
    agent: str
    capability: str
    score: float
    # the four factors, each in [0,1]
    capability_match: float
    trust: float
    budget: float
    availability: float
    # context for explainability / tie-breaking
    cost: float = 0.0
    affordable: bool = True
    available: bool = True
    rationale: str = ""


def budget_gate(cost: float, budget: float | None) -> float:
    """1.0 if the agent is affordable (or there's no ceiling), else 0.0 — a gate, not a
    preference. Cost still breaks ties among affordable agents (see the orchestrator)."""
    if budget is None or cost <= budget:
        return 1.0
    return 0.0


def score_fit(
    agent: str,
    capability: str,
    capability_match: float,
    profile: AgentProfile,
    budget: float | None,
) -> FitScore:
    trust = profile.weight()
    avail = 1.0 if profile.available else 0.0
    gate = budget_gate(profile.cost, budget)
    score = round(capability_match * trust * gate * avail, 6)
    affordable = gate > 0
    bits = [
        f"capability {capability_match:.3f}",
        f"trust {trust:.2f}",
        ("affordable" if affordable else f"priced out (cost {profile.cost} > budget {budget})"),
        ("available" if profile.available else "unavailable (benched)"),
    ]
    return FitScore(
        agent=agent,
        capability=capability,
        score=score,
        capability_match=round(capability_match, 6),
        trust=trust,
        budget=gate,
        availability=avail,
        cost=profile.cost,
        affordable=affordable,
        available=profile.available,
        rationale=" · ".join(bits),
    )
