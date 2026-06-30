"""Semantic matcher — ranks capabilities by embedding cosine similarity.

The genuinely-"semantic" backend the public page advertises. An :class:`Embedder` maps
the requirement and each capability into vectors; ranking is cosine similarity (not
lexical overlap). The least-privilege *scope proposal* is produced by an optional
:class:`Generator` (constrained JSON), and **falls back to the shared deterministic
extractor** if no generator is configured or its output is unusable — so the proposal
is always sane and the gateway is never weakened.

Hybrid by design: embedder and generator are independent and may be local or paid, in
any combination (see :mod:`praetor.matcher.factory`).
"""

from __future__ import annotations

import json
import math

from praetor.matcher._proposal import MUTATING, build_proposal
from praetor.matcher.base import CapabilityMatcher, MatchResult, RankedCapability, ScopeProposal
from praetor.matcher.providers.embedder import Embedder
from praetor.matcher.providers.generator import Generator
from praetor.models import Capability

_PROPOSAL_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": ["string", "null"]},
        "read_only": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
    "required": ["read_only", "rationale"],
}


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class SemanticMatcher(CapabilityMatcher):
    def __init__(self, embedder: Embedder, *, generator: Generator | None = None) -> None:
        self.embedder = embedder
        self.generator = generator
        gen = f"+{generator.name}" if generator else ""
        self.name = f"semantic[{embedder.name}{gen}]"

    def match(
        self,
        requirement: str,
        capabilities: list[tuple[str, Capability]],
        *,
        on_behalf_of: str = "",
    ) -> MatchResult:
        if not capabilities:
            return MatchResult(requirement=requirement, ranked=[], backend=self.name)

        texts = [f"{a} {c.name} {c.description} {c.targets or ''}".strip()
                 for a, c in capabilities]
        vectors = self.embedder.embed([requirement, *texts])
        query, cap_vecs = vectors[0], vectors[1:]

        ranked = sorted(
            (RankedCapability(agent=a, capability=c, score=round(max(0.0, _cosine(query, v)), 4))
             for (a, c), v in zip(capabilities, cap_vecs, strict=True)),
            key=lambda r: r.score, reverse=True,
        )
        result = MatchResult(requirement=requirement, ranked=ranked, backend=self.name)
        if ranked and ranked[0].score > 0:
            result.proposal = self._propose(requirement, ranked[0])
        return result

    # ── scope proposal: generator first, deterministic fallback ──────────────────
    def _propose(self, requirement: str, top: RankedCapability) -> ScopeProposal:
        prefix = f"semantic match (cosine {top.score}); "
        if self.generator is not None:
            proposal = self._generate(requirement, top, prefix)
            if proposal is not None:
                return proposal
        return build_proposal(requirement, top.agent, top.capability.name, rationale_prefix=prefix)

    def _generate(
        self, requirement: str, top: RankedCapability, prefix: str
    ) -> ScopeProposal | None:
        prompt = (
            "You propose a least-privilege scope for an agent capability.\n"
            f"Requirement: {requirement!r}\n"
            f"Chosen capability: {top.capability.name} (agent {top.agent})\n"
            "Reply ONLY with JSON: {\"target\": <id or null>, \"read_only\": <bool>, "
            "\"rationale\": <short string>}. `target` is the single resource the task "
            "names (e.g. host-9), or null. `read_only` is true if the task only reads."
        )
        try:
            data = json.loads(self.generator.generate(prompt, schema=_PROPOSAL_SCHEMA))
        except Exception:  # noqa: BLE001 - any generation/parse failure → deterministic fallback
            return None
        if not isinstance(data, dict) or "read_only" not in data:
            return None
        target = data.get("target") or None
        scope = {"target": str(target)} if target else {}
        excludes = list(MUTATING) if bool(data.get("read_only")) else []
        rationale = f"{prefix}{self.generator.name}: {data.get('rationale', '')}".strip()
        return ScopeProposal(
            agent=top.agent, capability=top.capability.name,
            scope=scope, excludes=excludes, rationale=rationale,
        )
