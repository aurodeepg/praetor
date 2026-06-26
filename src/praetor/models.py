"""Core data model for Praetor.

M1 introduced the atomic unit of authority — the *warrant* — and the kind of thing
it authorizes — a *tool call*. M2 adds the *agent identity* every warrant is bound
to. Later milestones add capability manifests, gateway decisions, and the audit
trail, each as its own increment.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

Trust = str  # free-form trust label, e.g. "internal", "3rd-party · prob.", "self-issued"

#: Why a warrant left the live set. ``manual`` (operator/orchestrator drop) and
#: ``ttl`` (lifetime elapsed) exist now; the rest are Phase-2 orchestrator triggers.
RevokeCause = Literal["manual", "ttl", "perf", "phase", "reputation"]


def _uid(prefix: str) -> str:
    # Full 128-bit uuid: these ids key the revocation ledger, so collisions (not
    # guessability — the JWT signature is the trust boundary) must be negligible.
    return f"{prefix}:{uuid.uuid4().hex}"


class AgentIdentity(BaseModel):
    """A verifiable identity the gateway issues to an agent.

    ``id`` is opaque to callers but meaningful to the identity backend — e.g.
    ``agent:containment:1a2b3c4d`` (local keypair backend). Warrants are bound to
    this id via their ``subject`` field.
    """

    id: str
    name: str
    trust: Trust = "unverified"
    issued_at: float = Field(default_factory=time.time)
    public_key: str | None = None  # PEM, when the backend exposes one


class Capability(BaseModel):
    """One thing an agent can do, as advertised to the registry.

    ``name`` is a dotted action namespace (``net.isolate``, ``logs.read``).
    ``targets`` optionally constrains what it may act on, as a glob (``logs:*``,
    ``host:*``). The registry answers "what *could* this agent do?"; a warrant is
    "what *may* it do right now?".
    """

    name: str
    description: str = ""
    targets: str | None = None  # glob over allowed targets; None = unconstrained


class CapabilityManifest(BaseModel):
    """What an agent publishes to the registry — its advertised capabilities."""

    agent: str
    description: str = ""
    capabilities: list[Capability] = Field(default_factory=list)


class ToolCall(BaseModel):
    """An agent's attempt to use a tool/capability through the gateway.

    ``action`` is a dotted (or colon-delimited) namespace such as ``net.isolate`` or
    ``logs.read``; ``target`` is the thing being acted on, e.g. ``host-9``.
    """

    agent: str                           # agent identity id making the call
    action: str                          # dotted action, e.g. "net.isolate"
    target: str | None = None            # the thing acted on, e.g. "db-prod-12"
    args: dict[str, Any] = Field(default_factory=dict)


class Warrant(BaseModel):
    """The unit of authority — a single scoped, time-boxed, revocable grant.

    A warrant is *least-privilege* (one ``capability``, narrowed by ``scope`` with
    explicit ``excludes``), *time-boxed* (``issued_at``/``expires_at``), and
    *revocable* (the ``revoked`` flag, flipped by the ledger so the very next call is
    denied at the gateway).

    Whether a warrant *covers* a given call is pure scope matching (see
    :mod:`praetor.warrants.scope`); whether it is *currently valid* (not expired, not
    revoked) is a separate, time-dependent check — kept apart so each is easy to
    reason about and test.
    """

    wid: str = Field(default_factory=lambda: _uid("w"))
    subject: str                         # agent identity id this warrant is bound to
    on_behalf_of: str                    # the requester / task, e.g. incident://ir-4821
    capability: str                      # the granted action (may be a dotted prefix)
    scope: dict[str, str] = Field(default_factory=dict)   # e.g. {"target": "db-prod-12"}
    excludes: list[str] = Field(default_factory=list)     # explicitly denied actions
    trust: Trust = "unverified"
    reason: str = ""

    issued_at: float = 0.0
    expires_at: float = 0.0
    token: str | None = None             # signed JWT carrying the claims above

    revoked: bool = False
    revoked_at: float | None = None
    revoke_cause: RevokeCause | None = None
    revoke_reason: str | None = None

    def is_active(self, now: float) -> bool:
        """Currently valid: not revoked and within the [issued_at, expires_at) window."""
        return not self.revoked and self.issued_at <= now < self.expires_at

    def remaining(self, now: float) -> float:
        """Seconds of authority left (0 once expired or revoked)."""
        if self.revoked:
            return 0.0
        return max(0.0, self.expires_at - now)

    @property
    def ttl(self) -> float:
        """Total lifetime of the warrant in seconds."""
        return max(0.0, self.expires_at - self.issued_at)


class Decision(BaseModel):
    """The gateway's verdict for a single call."""

    allow: bool
    reason: str
    warrant_id: str | None = None        # the warrant that authorized an allow
    call: ToolCall
    decided_at: float = Field(default_factory=time.time)

    @property
    def verdict(self) -> str:
        return "ALLOW" if self.allow else "DENY"


class AuditEntry(BaseModel):
    """One immutable line in the provenance trail.

    Every issuance, revocation, and decision lands here, bound to the identity and
    the warrant involved — the trail that proves what each agent was, and wasn't,
    allowed to do.
    """

    ts: float = Field(default_factory=time.time)
    kind: Literal["issue", "revoke", "decision"]
    subject: str | None = None
    warrant_id: str | None = None
    action: str | None = None
    decision: str | None = None          # "ALLOW" / "DENY" for decision entries
    cause: str | None = None             # revoke cause
    detail: str = ""
