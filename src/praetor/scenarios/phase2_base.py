"""Shared base for the Phase-2 (orchestrator-driven) scenarios.

Phase-1 scenarios issue warrants on explicit beats; Phase-2 scenarios hand the
decisions to the :class:`~praetor.orchestrator.Orchestrator`, which scores team fit
(capability × trust × budget × availability) and recomposes the team itself. This base
adds one helper — a frame that *shows the fit maths* behind an admission — so every
Phase-2 scenario explains why the orchestrator chose who it chose.
"""

from __future__ import annotations

from praetor.orchestrator import Composition
from praetor.scenarios.base import Frame, Scenario


class Phase2Scenario(Scenario):
    def _admit_frame(self, phase: str, comp: Composition, cls: str = "gold") -> Frame:
        f = comp.fit
        return self._frame(
            phase,
            f"Orchestrator scores team fit and admits {comp.chosen} "
            f"(fit {f.score:.3f} = cap {f.capability_match:.2f} × trust {f.trust:.2f} "
            f"× budget {f.budget:.0f} × avail {f.availability:.0f}).",
            "ISSUE", cls, f"warrant issued · {comp.chosen} · {f.capability}", f.rationale)
