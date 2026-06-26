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

from praetor.matcher.base import (
    CapabilityMatcher,
    MatchResult,
    RankedCapability,
    ScopeProposal,
)
from praetor.models import Capability

_WORD = re.compile(r"[a-z0-9]+")
# A compound host/id-looking token kept whole: db-prod-12, host-9, 8.8.8.8, web_3.
_TARGETISH = re.compile(r"[A-Za-z0-9]+(?:[.\-_][A-Za-z0-9]+)+")
_TOKEN = re.compile(r"[A-Za-z0-9]+")
_MUTATING = ["write", "remediate", "delete", "modify", "deploy", "isolate", "quarantine"]
_READONLY_HINTS = ("read", "look", "inspect", "enrich", "analyz", "review", "audit", "triage")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _score(requirement: str, cap: Capability, agent: str) -> float:
    req = _tokens(requirement)
    hay = _tokens(f"{agent} {cap.name} {cap.description} {cap.targets or ''}")
    overlap = len(req & hay) / (len(req) or 1)
    fuzzy = SequenceMatcher(None, requirement.lower(), cap.name.lower()).ratio()
    return round(0.7 * overlap + 0.3 * fuzzy, 4)


def _guess_target(requirement: str, cap: Capability) -> str | None:
    # Prefer a compound host/id-looking token captured whole (db-prod-12, host-9,
    # 8.8.8.8) — splitting it would propose a too-broad/wrong scope like "12".
    m = _TARGETISH.search(requirement)
    if m:
        return m.group(0)
    # Otherwise fall back to a lone token that carries a digit (e.g. "node7").
    for tok in _TOKEN.findall(requirement):
        if any(ch.isdigit() for ch in tok):
            return tok
    return None


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
            target = _guess_target(requirement, top.capability)
            readonly = any(h in requirement.lower() for h in _READONLY_HINTS)
            excludes = list(_MUTATING) if readonly else []
            scope = {"target": target} if target else {}
            result.proposal = ScopeProposal(
                agent=top.agent,
                capability=top.capability.name,
                scope=scope,
                excludes=excludes,
                rationale=(
                    f"best lexical fit ({top.score}); "
                    + (f"scoped to target {target}; " if target
                       else "no specific target detected; ")
                    + ("read-only requirement → mutating verbs excluded"
                       if readonly else "no exclusions inferred")
                ),
            )
        return result
