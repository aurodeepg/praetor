"""Shared plumbing for replayable scenarios.

Every scenario drives the *real* gateway: it registers a roster of adapters, then a
``play()`` walks an evolving task — issuing, enforcing, and revoking scoped authority
as it goes. The gateway produces every verdict; the scenario only decides *what* to
attempt.

Concrete adapters are deliberately **swappable**. A role backed by a ``MockAdapter``
here behaves identically to one backed by HTTP / MCP / a provider SDK, because
enforcement happens *before* ``invoke`` and the verdict comes from the live ledger,
not the adapter. So a scenario can name a real third-party agent (a Claude Agent SDK
forensics agent, a Postgres MCP server, …) via the role's ``name``/``trust`` while
staying deterministic and dependency-free for tests and CI.
"""

from __future__ import annotations

from collections.abc import Iterator

from pydantic import BaseModel, Field

from praetor.adapters.base import AgentAdapter
from praetor.gateway import Gateway


class _Clock:
    """A hand-cranked clock so TTL expiry is deterministic in a replay."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, dt: float) -> None:
        self.t += dt


class LedgerRow(BaseModel):
    agent: str
    capability: str
    scope: str
    trust: str
    remaining: int
    ttl: int


class Frame(BaseModel):
    """One beat of a replay: a narrated action, the gateway's verdict, and the state
    of live authority right after it."""

    phase: str
    narration: str
    badge: str                  # ISSUE / ALLOW / DENY / REVOKE / EXPIRE
    cls: str                    # info / allow / deny / warn / gold  (renderer styling)
    message: str
    reason: str = ""
    ledger: list[LedgerRow] = Field(default_factory=list)


class Scenario:
    """Base for a replayable scenario: a roster of adapters + a ``play()`` of beats.

    Subclasses set :attr:`title`, build their roster in ``__init__`` (calling
    ``super().__init__(adapters)``), and implement :meth:`play`.
    """

    title: str = "scenario"

    def __init__(self, adapters: list[AgentAdapter]) -> None:
        self.clock = _Clock()
        self.gateway = Gateway(clock=self.clock)
        self.ids = {a.name: self.gateway.register(a).id for a in adapters}
        self._name_of = {wid: name for name, wid in self.ids.items()}

    # ── ledger view (resolve subject ids back to readable names) ─────────────────
    def _ledger(self) -> list[LedgerRow]:
        now = self.gateway.now()
        return [
            LedgerRow(
                agent=self._name_of.get(w.subject, w.subject),
                capability=w.capability,
                scope=str(w.scope.get("target", "—")),
                trust=w.trust,
                remaining=int(w.remaining(now)),
                ttl=int(w.ttl),
            )
            for w in self.gateway.active_warrants()
        ]

    def _frame(self, phase, narration, badge, cls, message, reason="") -> Frame:
        return Frame(phase=phase, narration=narration, badge=badge, cls=cls,
                     message=message, reason=reason, ledger=self._ledger())

    def play(self) -> Iterator[Frame]:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self) -> tuple[Gateway, list[Frame]]:
        """Run the replay; return the gateway plus all frames (verdicts are real)."""
        return self.gateway, list(self.play())
