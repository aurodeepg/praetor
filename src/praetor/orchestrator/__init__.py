"""The Phase-2 orchestrator — requirement-driven team evolution.

The gateway reasons about **team fit = capability × trust × budget × availability** and
recomposes the team by issuing/revoking warrants. Deterministic by default (a semantic
matcher backend, M10, can sharpen the capability factor later). Layers on top of the
gateway; never inside enforcement.
"""

from praetor.orchestrator.fit import FitScore, budget_gate, score_fit
from praetor.orchestrator.orchestrator import Composition, Orchestrator
from praetor.orchestrator.profile import AgentProfile, default_trust_weight

__all__ = [
    "AgentProfile",
    "Composition",
    "FitScore",
    "Orchestrator",
    "budget_gate",
    "default_trust_weight",
    "score_fit",
]
