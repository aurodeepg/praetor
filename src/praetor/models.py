"""Core data model for Praetor.

M1 introduces just the atomic unit of authority — the *warrant* — and the kind of
thing it authorizes — a *tool call*. Later milestones add identities, capability
manifests, gateway decisions, and the audit trail, each as its own increment.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field

Trust = str  # free-form trust label, e.g. "internal", "3rd-party · prob.", "self-issued"


def _uid(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4().hex[:8]}"


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
    *revocable* (the ``revoked`` flag, flipped by the ledger in a later milestone, so
    the very next call is denied at the gateway).

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

    revoked: bool = False

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
