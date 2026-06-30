"""Deterministic matcher — lexical / fuzzy ranking, no model, $0, fully offline.

The default. Ranks capabilities by token overlap + fuzzy similarity against the
requirement, extracts a likely target, and proposes a conservative least-privilege
scope (read-only requirements exclude mutating verbs). Good enough to drive the demo,
and a sensible floor that never costs anything — the ``local`` SLM and ``claude``
backends layer on top later without changing this contract.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from praetor.matcher._proposal import build_proposal
from praetor.matcher.base import CapabilityMatcher, MatchResult, RankedCapability
from praetor.models import Capability

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _score(requirement: str, cap: Capability, agent: str) -> float:
    req = _tokens(requirement)
    hay = _tokens(f"{agent} {cap.name} {cap.description} {cap.targets or ''}")
    overlap = len(req & hay) / (len(req) or 1)
    fuzzy = SequenceMatcher(None, requirement.lower(), cap.name.lower()).ratio()
    return round(0.7 * overlap + 0.3 * fuzzy, 4)


class DeterministicMatcher(CapabilityMatcher):
    name = "deterministic"

    def match(
        self,
        requirement: str,
        capabilities: list[tuple[str, Capability]],
        *,
        on_behalf_of: str = "",
    ) -> MatchResult:
        ranked = sorted(
            (RankedCapability(agent=a, capability=c, score=_score(requirement, c, a))
             for a, c in capabilities),
            key=lambda r: r.score,
            reverse=True,
        )
        result = MatchResult(requirement=requirement, ranked=ranked, backend=self.name)

        if ranked and ranked[0].score > 0:
            top = ranked[0]
            result.proposal = build_proposal(
                requirement, top.agent, top.capability.name,
                rationale_prefix=f"best lexical fit ({top.score}); ",
            )
        return result
