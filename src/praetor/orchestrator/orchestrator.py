"""The Phase-2 orchestrator — the gateway *decides* team composition.

Phase 1 issues warrants on explicit request; Phase 2 reasons about **team fit**
(capability × trust × budget × availability) and recomposes the team itself by issuing
and revoking warrants as requirements, performance, and budget shift. Team membership
*is* the set of valid warrants, so "admit" = issue and "drop" = revoke.

The orchestrator sits *on top of* the gateway's public surface (registry, matcher,
issue/revoke, the live ledger). It never reaches inside enforcement — composition
reasoning and authority enforcement stay separate, by design. Composition is
deterministic here; a semantic matcher backend (M10) can sharpen the capability factor
without touching this logic.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from praetor.gateway import Gateway
from praetor.matcher.base import CapabilityMatcher
from praetor.orchestrator.fit import FitScore, score_fit
from praetor.orchestrator.profile import AgentProfile

#: Below this rolling performance, an agent is benched and its tasks recomposed.
DEFAULT_PERF_THRESHOLD = 0.6
#: How much a single failure drops performance (1.0 → 0.5 trips the default threshold).
DEFAULT_PERF_DECREMENT = 0.5


class Composition(BaseModel):
    """The outcome of a (re)composition decision: who was chosen and why."""

    requirement: str
    on_behalf_of: str
    chosen: str | None = None
    warrant_id: str | None = None
    fit: FitScore | None = None
    ranked: list[FitScore] = Field(default_factory=list)
    note: str = ""


class Orchestrator:
    def __init__(
        self,
        gateway: Gateway,
        *,
        matcher: CapabilityMatcher | None = None,
        budget: float | None = None,
        perf_threshold: float = DEFAULT_PERF_THRESHOLD,
        perf_decrement: float = DEFAULT_PERF_DECREMENT,
    ) -> None:
        self.gw = gateway
        self.matcher = matcher or gateway.matcher
        self.budget = budget
        self.perf_threshold = perf_threshold
        self.perf_decrement = perf_decrement
        self.profiles: dict[str, AgentProfile] = {}
        self._tasks: dict[str, str] = {}  # on_behalf_of -> requirement (for recomposition)
        self._rankings: dict[str, list[FitScore]] = {}  # on_behalf_of -> last ranking

    # ── profiles ─────────────────────────────────────────────────────────────────
    def set_profile(self, profile: AgentProfile) -> None:
        self.profiles[profile.agent] = profile

    def profile(self, agent: str, trust: str = "unverified") -> AgentProfile:
        return self.profiles.setdefault(agent, AgentProfile(agent=agent, trust=trust))

    def sync_profiles_from_gateway(self) -> None:
        """Create a default profile for every registered agent that doesn't have one yet,
        pulling its trust label from the gateway identity. Cost/availability take defaults
        (free, available) until set explicitly — so the orchestrator works against any
        gateway out of the box, ranking on capability × trust."""
        for name, ident in self.gw.identities().items():
            if name not in self.profiles:
                self.profiles[name] = AgentProfile(agent=name, trust=ident.trust)

    # ── ranking ──────────────────────────────────────────────────────────────────
    def rank(self, requirement: str, *, exclude: set[str] | None = None) -> list[FitScore]:
        """Score every agent's best-matching capability for the requirement, then sort by
        fit (desc), cheaper first as a tie-break, then name for full determinism."""
        exclude = exclude or set()
        match = self.matcher.match(requirement, self.gw.registry.capabilities())

        # best capability-match score per agent (and which capability earned it)
        best: dict[str, tuple[str, float]] = {}
        for rc in match.ranked:
            cur = best.get(rc.agent)
            if cur is None or rc.score > cur[1]:
                best[rc.agent] = (rc.capability.name, rc.score)

        scores = [
            score_fit(agent, cap, cap_match, self.profile(agent), self.budget)
            for agent, (cap, cap_match) in best.items()
            if agent not in exclude
        ]
        scores.sort(key=lambda f: (-f.score, f.cost, f.agent))
        return scores

    # ── composition ──────────────────────────────────────────────────────────────
    def compose(
        self,
        requirement: str,
        *,
        on_behalf_of: str,
        ttl: float | None = None,
        exclude: set[str] | None = None,
    ) -> Composition:
        """Pick the best-fit agent and admit it: issue a least-privilege warrant (scope
        from the matcher proposal). Returns the decision, including the full ranking."""
        self._tasks[on_behalf_of] = requirement
        ranked = self.rank(requirement, exclude=exclude)
        self._rankings[on_behalf_of] = ranked
        viable = [f for f in ranked if f.score > 0]
        if not viable:
            return Composition(
                requirement=requirement, on_behalf_of=on_behalf_of, ranked=ranked,
                note="no viable agent (capability/trust/budget/availability)")

        top = viable[0]
        proposal = self.matcher.match(
            requirement, self.gw.registry.capabilities(), on_behalf_of=on_behalf_of
        ).proposal
        scope = proposal.scope if proposal else {}
        excludes = proposal.excludes if proposal else []
        prof = self.profile(top.agent)
        warrant = self.gw.issue_warrant(
            subject=top.agent, on_behalf_of=on_behalf_of, capability=top.capability,
            scope=scope, excludes=excludes, ttl=ttl, trust=prof.trust,
            reason=f"orchestrator: best fit {top.score:.3f} ({top.rationale})",
        )
        return Composition(
            requirement=requirement, on_behalf_of=on_behalf_of, chosen=top.agent,
            warrant_id=warrant.wid, fit=top, ranked=ranked,
            note=f"admitted {top.agent} (fit {top.score:.3f})",
        )

    # ── triggers that reshape the team ───────────────────────────────────────────
    def report_performance(self, agent: str, ok: bool) -> list[Composition]:
        """Feed an outcome back. A success nudges performance up; a failure drops it, and
        if it falls below threshold the agent is **benched and its tasks recomposed** to
        the next-best fit — the "an agent underperforms and gets swapped" beat."""
        prof = self.profile(agent)
        if ok:
            prof.performance = min(1.0, prof.performance + 0.25)
            return []
        prof.performance = max(0.0, prof.performance - self.perf_decrement)
        if prof.performance >= self.perf_threshold:
            return []
        prof.available = False  # benched → availability factor goes to 0
        return self._recompose_tasks_of(
            agent, cause="perf",
            reason=f"perf {prof.performance:.2f} < {self.perf_threshold}")

    def set_budget(self, budget: float | None) -> list[Composition]:
        """Change the budget ceiling and recompose any task whose current holder is now
        priced out — the "a budget gate promotes a cheaper specialist" beat."""
        self.budget = budget
        out: list[Composition] = []
        for obo, req in list(self._tasks.items()):
            holders = self._task_holders(obo)
            priced_out = (
                [a for a in holders if self.profile(a).cost > budget]
                if budget is not None else []
            )
            if priced_out:
                for a in priced_out:
                    self._revoke_agent_task(a, obo, cause="phase", reason="budget gate: priced out")
                out.append(self.compose(req, on_behalf_of=obo, exclude=set(priced_out)))
        return out

    def release(self, on_behalf_of: str, *, cause: str = "phase", reason: str = "") -> None:
        """Drop the whole team for a finished task/phase — revoke all its warrants."""
        for w in self._warrants_for_task(on_behalf_of):
            self.gw.revoke(w.wid, cause=cause, reason=reason or f"released ({cause})")
        self._tasks.pop(on_behalf_of, None)

    # ── views ────────────────────────────────────────────────────────────────────
    def snapshot(self) -> dict:
        """An inspectable view of the orchestrator's reasoning: the budget, per-agent
        profiles, and the most recent fit ranking per task (full factor breakdown)."""
        return {
            "budget": self.budget,
            "profiles": {a: p.model_dump() for a, p in self.profiles.items()},
            "rankings": {
                obo: [f.model_dump() for f in ranked]
                for obo, ranked in self._rankings.items()
            },
        }

    # ── internals ────────────────────────────────────────────────────────────────
    def _warrants_for_task(self, on_behalf_of: str) -> list:
        return [w for w in self.gw.active_warrants() if w.on_behalf_of == on_behalf_of]

    def _task_holders(self, on_behalf_of: str) -> list[str]:
        ids = {w.subject for w in self._warrants_for_task(on_behalf_of)}
        return [a for a in self.profiles if self.gw.subject_for(a) in ids] or [
            a for a in self.gw.registry.agents() if self.gw.subject_for(a) in ids
        ]

    def _revoke_agent_task(self, agent: str, on_behalf_of: str, *, cause: str, reason: str) -> None:
        sid = self.gw.subject_for(agent)
        for w in self._warrants_for_task(on_behalf_of):
            if w.subject == sid:
                self.gw.revoke(w.wid, cause=cause, reason=reason)

    def _recompose_tasks_of(self, agent: str, *, cause: str, reason: str) -> list[Composition]:
        sid = self.gw.subject_for(agent)
        affected = {w.on_behalf_of for w in self.gw.active_warrants() if w.subject == sid}
        out: list[Composition] = []
        for obo in affected:
            self._revoke_agent_task(agent, obo, cause=cause, reason=reason)
            req = self._tasks.get(obo)
            if req:
                out.append(self.compose(req, on_behalf_of=obo, exclude={agent}))
        return out
