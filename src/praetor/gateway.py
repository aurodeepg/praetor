"""The Praetor gateway — issue · enforce · revoke, all through one point.

This is the authority core and the single façade the CLI, the API, and the scenarios
will drive. It wires together the identity backend, the warrant issuer, the live
ledger, enforcement, and the audit trail, and exposes the small surface everything
else needs. (The capability registry, capability-matcher, and agent adapters arrive
in later milestones and layer on top — never inside enforcement.)

The gateway carries an injectable ``clock`` so it can run on either wall-clock time
(the real product) or a logical tick (deterministic demos/tests) without changing a
line of the core logic.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from praetor.adapters.base import AgentAdapter
from praetor.audit import AuditLog
from praetor.enforcement import decide
from praetor.identity import LocalIdentityProvider
from praetor.identity.base import IdentityProvider
from praetor.matcher import CapabilityMatcher, DeterministicMatcher, MatchResult
from praetor.models import (
    AgentIdentity,
    AuditEntry,
    Capability,
    CapabilityManifest,
    Decision,
    RevokeCause,
    ToolCall,
    ToolResult,
    Warrant,
)
from praetor.registry import CapabilityRegistry
from praetor.warrants.issuer import WarrantIssuer
from praetor.warrants.ledger import WarrantLedger

#: Default warrant lifetime (seconds) when a caller doesn't specify one. Short-lived
#: by design — least-privilege in the time dimension, and a backstop to revocation.
DEFAULT_WARRANT_TTL = 300.0


class Gateway:
    def __init__(
        self,
        identity: IdentityProvider | None = None,
        matcher: CapabilityMatcher | None = None,
        clock: Callable[[], float] = time.time,
        warrant_ttl_default: float = DEFAULT_WARRANT_TTL,
    ) -> None:
        self._clock = clock
        self.warrant_ttl_default = warrant_ttl_default

        self.identity = identity or LocalIdentityProvider()
        self.matcher = matcher or DeterministicMatcher()
        self.registry = CapabilityRegistry()
        self.ledger = WarrantLedger()
        self.issuer = WarrantIssuer(self.identity)
        self.audit = AuditLog()

        self._identities: dict[str, AgentIdentity] = {}  # agent name -> identity
        self._adapters: dict[str, AgentAdapter] = {}     # identity id -> adapter

    # ── clock ──────────────────────────────────────────────────────────────────
    def now(self) -> float:
        return self._clock()

    def set_clock(self, clock: Callable[[], float]) -> None:
        self._clock = clock

    # ── identity ───────────────────────────────────────────────────────────────
    def register_agent(
        self,
        name: str,
        trust: str = "unverified",
        capabilities: list[Capability] | None = None,
        description: str = "",
    ) -> AgentIdentity:
        """Admit an agent: issue it a verifiable identity and, if it advertises any,
        register its capability manifest.

        Registration grants *no* authority on its own — the agent still can't do
        anything until it holds a warrant. Identity is who it is; the manifest is what
        it *could* do; a warrant is what it *may* do right now.
        """
        identity = self.identity.issue_identity(name, trust=trust)
        self._identities[name] = identity
        if capabilities is not None or description:
            self.registry.register(CapabilityManifest(
                agent=name, description=description, capabilities=capabilities or [],
            ))
        return identity

    def register(self, adapter: AgentAdapter) -> AgentIdentity:
        """Admit an agent *by its adapter*: issue identity, register the adapter's
        manifest, and wire the adapter so the gateway can dispatch authorized calls to
        it. Like :meth:`register_agent`, this grants no authority on its own."""
        identity = self.identity.issue_identity(adapter.name, trust=adapter.trust)
        self._identities[adapter.name] = identity
        manifest = adapter.manifest()
        manifest.agent = adapter.name
        self.registry.register(manifest)
        self._adapters[identity.id] = adapter
        return identity

    def subject_for(self, name_or_id: str) -> str:
        """Resolve an agent name to its identity id; pass through unknown strings."""
        ident = self._identities.get(name_or_id)
        return ident.id if ident else name_or_id

    # ── warrants ───────────────────────────────────────────────────────────────
    def issue_warrant(
        self,
        *,
        subject: str,
        on_behalf_of: str,
        capability: str,
        scope: dict[str, str] | None = None,
        excludes: list[str] | None = None,
        ttl: float | None = None,
        trust: str = "unverified",
        reason: str = "",
    ) -> Warrant:
        """Mint a signed, scoped, time-boxed warrant and drop it into the live ledger."""
        subject_id = self.subject_for(subject)
        warrant = self.issuer.mint(
            subject=subject_id,
            on_behalf_of=on_behalf_of,
            capability=capability,
            scope=scope,
            excludes=excludes,
            ttl=ttl if ttl is not None else self.warrant_ttl_default,
            now=self.now(),
            trust=trust,
            reason=reason,
        )
        self.ledger.issue(warrant)
        self.audit.record(AuditEntry(
            ts=self.now(), kind="issue", subject=subject_id, warrant_id=warrant.wid,
            action=capability, detail=reason or f"warrant issued · {capability}",
        ))
        return warrant

    def revoke(self, wid: str, cause: RevokeCause = "manual", reason: str = "") -> Warrant | None:
        """Revoke a warrant. The next call by its holder is denied at the gateway."""
        warrant = self.ledger.revoke(wid, self.now(), cause=cause, reason=reason)
        if warrant:
            self.audit.record(AuditEntry(
                ts=self.now(), kind="revoke", subject=warrant.subject, warrant_id=wid,
                cause=cause, detail=reason or f"revoked ({cause})",
            ))
        return warrant

    # ── enforcement ────────────────────────────────────────────────────────────
    def enforce(self, call: ToolCall) -> Decision:
        """The policy enforcement point. Auto-expires TTL-elapsed warrants first, then
        decides against the live ledger and records the verdict."""
        for expired in self.ledger.expire_due(self.now()):
            self.audit.record(AuditEntry(
                ts=self.now(), kind="revoke", subject=expired.subject,
                warrant_id=expired.wid, cause="ttl", detail=expired.revoke_reason or "",
            ))
        decision = decide(self.ledger, call, self.now())
        self.audit.record(AuditEntry(
            ts=self.now(), kind="decision", subject=self.subject_for(call.agent),
            warrant_id=decision.warrant_id, action=call.action,
            decision=decision.verdict, detail=decision.reason,
        ))
        return decision

    def dispatch(self, call: ToolCall) -> tuple[Decision, ToolResult | None]:
        """Enforce, then — only if allowed — run the agent's adapter. A denied call
        never reaches ``invoke``: the gateway is the policy enforcement point that sits
        between intent and action."""
        decision = self.enforce(call)
        if not decision.allow:
            return decision, None
        adapter = self._adapters.get(self.subject_for(call.agent)) \
            or self._adapters.get(call.agent)
        if adapter is None:
            return decision, ToolResult(ok=False, error="no adapter registered for agent")
        return decision, adapter.invoke(call)

    # ── matcher (the cheap AI seed) ──────────────────────────────────────────────
    def match(self, requirement: str, on_behalf_of: str = "") -> MatchResult:
        """Map a free-form requirement to registered capabilities + a proposed
        least-privilege scope. This only *proposes* — issuing authority stays an
        explicit :meth:`issue_warrant` call (optionally fed by the proposal)."""
        return self.matcher.match(
            requirement, self.registry.capabilities(), on_behalf_of=on_behalf_of
        )

    # ── views ──────────────────────────────────────────────────────────────────
    def active_warrants(self) -> list[Warrant]:
        return self.ledger.active(self.now())

    def snapshot(self) -> dict:
        """A redacted, UI-friendly view of live authority + the recent audit trail."""
        now = self.now()
        return {
            "now": now,
            "agents": self.registry.agents(),
            "warrants": [
                {**w.model_dump(exclude={"token"}), "remaining": w.remaining(now)}
                for w in self.active_warrants()
            ],
            "audit": [e.model_dump() for e in self.audit.entries(limit=12)],
        }
