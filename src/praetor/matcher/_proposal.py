"""Shared least-privilege scope extraction, used by every matcher backend.

Ranking differs by backend (lexical for `deterministic`, cosine for `semantic`), but
the *scope proposal* — pull a likely target, lock out mutating verbs for read-only
intents — is the same conservative logic everywhere. Centralised here so the backends
can't drift, and so a generative backend can fall back to it when it declines to
produce a structured proposal.
"""

from __future__ import annotations

import re

from praetor.matcher.base import ScopeProposal

# A compound host/id-looking token kept whole: db-prod-12, host-9, 8.8.8.8, web_3.
_TARGETISH = re.compile(r"[A-Za-z0-9]+(?:[.\-_][A-Za-z0-9]+)+")
_TOKEN = re.compile(r"[A-Za-z0-9]+")

#: Verbs a read-only requirement must never be allowed to perform (defense in depth).
MUTATING = ["write", "remediate", "delete", "modify", "deploy", "isolate", "quarantine"]
_READONLY_HINTS = ("read", "look", "inspect", "enrich", "analyz", "review", "audit", "triage")


def guess_target(requirement: str) -> str | None:
    """A likely target id from the requirement, kept whole (no splitting db-prod-12 → 12)."""
    m = _TARGETISH.search(requirement)
    if m:
        return m.group(0)
    for tok in _TOKEN.findall(requirement):
        if any(ch.isdigit() for ch in tok):
            return tok
    return None


def is_readonly(requirement: str) -> bool:
    return any(h in requirement.lower() for h in _READONLY_HINTS)


def build_proposal(
    requirement: str, agent: str, capability: str, *, rationale_prefix: str = ""
) -> ScopeProposal:
    """A conservative least-privilege proposal: target-scoped, mutating verbs excluded for
    read-only intents. ``rationale_prefix`` lets each backend note *why* it chose the pair."""
    target = guess_target(requirement)
    readonly = is_readonly(requirement)
    scope = {"target": target} if target else {}
    excludes = list(MUTATING) if readonly else []
    rationale = (
        rationale_prefix
        + (f"scoped to target {target}; " if target else "no specific target detected; ")
        + ("read-only requirement → mutating verbs excluded" if readonly
           else "no exclusions inferred")
    )
    return ScopeProposal(
        agent=agent, capability=capability, scope=scope, excludes=excludes, rationale=rationale
    )
