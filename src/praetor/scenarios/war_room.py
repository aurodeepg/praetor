"""The incident-response war room — Phase 1, replayed through the *real* gateway.

An incident evolves (triage → contain → forensics → wrap-up) and the gateway issues,
enforces, and revokes scoped authority as it goes. Every verdict here is produced by
the live gateway, not scripted — the scenario only decides *what* to attempt; the
gateway decides what's *allowed*.

`play()` returns the gateway plus an ordered list of :class:`Frame`s (one per beat),
so the CLI can render them and tests can assert on the verdicts.
"""

from __future__ import annotations

from collections.abc import Iterator

from pydantic import BaseModel, Field

from praetor.gateway import Gateway
from praetor.models import ToolCall
from praetor.scenarios.seed import seed_war_room_agents


class _Clock:
    """A hand-cranked clock so TTL expiry is deterministic in the replay."""

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
    """One beat of the replay: a narrated action, the gateway's verdict, and the
    state of live authority right after it."""

    phase: str
    narration: str
    badge: str                  # ISSUE / ALLOW / DENY / REVOKE / EXPIRE
    cls: str                    # info / allow / deny / warn / gold  (renderer styling)
    message: str
    reason: str = ""
    ledger: list[LedgerRow] = Field(default_factory=list)


class WarRoom:
    def __init__(self) -> None:
        self.clock = _Clock()
        self.gateway = Gateway(clock=self.clock)
        self.ids = seed_war_room_agents(self.gateway)
        self._name_of = {wid: name for name, wid in self.ids.items()}

    # ── ledger view (resolve subject ids back to readable names) ────────────────
    def _ledger(self) -> list[LedgerRow]:
        now = self.gateway.now()
        rows = []
        for w in self.gateway.active_warrants():
            rows.append(LedgerRow(
                agent=self._name_of.get(w.subject, w.subject),
                capability=w.capability,
                scope=str(w.scope.get("target", "—")),
                trust=w.trust,
                remaining=int(w.remaining(now)),
                ttl=int(w.ttl),
            ))
        return rows

    def _frame(self, phase, narration, badge, cls, message, reason="") -> Frame:
        return Frame(phase=phase, narration=narration, badge=badge, cls=cls,
                     message=message, reason=reason, ledger=self._ledger())

    # ── the replay ──────────────────────────────────────────────────────────────
    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        c_id, f_id, i_id = self.ids["containment"], self.ids["forensics"], self.ids["threat-intel"]

        # 1 ─ TRIAGE: forensics gets a read-only, log-scoped grant.
        gw.issue_warrant(
            subject="forensics", on_behalf_of="incident://ir-4821", capability="logs.read",
            scope={"target": "logs:auth-*"}, trust="internal · read-only", ttl=600,
            reason="triage: inspect auth logs for the intrusion",
        )
        yield self._frame("TRIAGE", "Forensics is admitted read-only to triage the auth logs.",
                          "ISSUE", "info", "warrant issued · forensics · logs.read → logs:auth-*")

        d = gw.enforce(ToolCall(agent=f_id, action="logs.read", target="logs:auth-12"))
        yield self._frame("TRIAGE", "Forensics reads the scoped logs.",
                          d.verdict, "allow", "forensics · logs.read(logs:auth-12)", d.reason)

        # 2 ─ CONTAIN: the matcher proposes a least-privilege grant; we approve it.
        match = gw.match("isolate the compromised host host-9", on_behalf_of="incident://ir-4821")
        prop = match.proposal
        target = prop.scope.get("target")
        gw.issue_warrant(
            subject=prop.agent, on_behalf_of="incident://ir-4821", capability=prop.capability,
            scope=prop.scope, excludes=["fs.write", "remediate"],
            trust="internal · high-priv", ttl=300,
            reason="contain lateral movement on host-9",
        )
        yield self._frame("CONTAIN",
                          f"Matcher proposes least privilege → {prop.agent} · {prop.capability} "
                          f"scoped to {target}. Approved.",
                          "ISSUE", "gold",
                          f"warrant issued · containment · net.isolate → {target}")

        d = gw.enforce(ToolCall(agent=c_id, action="net.isolate", target="host-9"))
        yield self._frame("CONTAIN", "Containment isolates the host it was scoped for.",
                          d.verdict, "allow", "containment · net.isolate(host-9)", d.reason)

        # 3 ─ ESCALATION BLOCKED: same agent, beyond its scope and outside its capability.
        d = gw.enforce(ToolCall(agent=c_id, action="net.isolate", target="host-prod-1"))
        yield self._frame("CONTAIN", "Containment reaches for a host it was NOT scoped for.",
                          d.verdict, "deny", "containment · net.isolate(host-prod-1)", d.reason)

        d = gw.enforce(ToolCall(agent=c_id, action="fs.write", target="host-9"))
        yield self._frame("CONTAIN", "Containment tries to escalate to a destructive write.",
                          d.verdict, "deny", "containment · fs.write(host-9)", d.reason)

        # 4 ─ UNTRUSTED INTEL: a narrow, short-lived grant to a third party.
        gw.issue_warrant(
            subject="threat-intel", on_behalf_of="incident://ir-4821", capability="intel.lookup",
            trust="3rd-party · prob.", ttl=120,
            reason="enrich the attacker IP — narrow, expiring, untrusted",
        )
        yield self._frame("FORENSICS", "A third-party intel agent gets a narrow, 120s grant.",
                          "ISSUE", "warn",
                          "warrant issued · threat-intel · intel.lookup (ttl 120s)")

        d = gw.enforce(ToolCall(agent=i_id, action="intel.lookup", target="8.8.8.8"))
        yield self._frame("FORENSICS",
                          "Intel enriches the indicator — exactly what it's scoped for.",
                          d.verdict, "allow",
                          "threat-intel · intel.lookup(8.8.8.8)", d.reason)

        d = gw.enforce(ToolCall(agent=i_id, action="logs.read", target="logs:auth-12"))
        yield self._frame("FORENSICS",
                          "The untrusted agent reaches for logs it was never granted.",
                          d.verdict, "deny",
                          "threat-intel · logs.read(logs:auth-12)", d.reason)

        # 5 ─ REVOKE: containment is done — drop the privilege; the next call dies.
        for w in gw.active_warrants():
            if self._name_of.get(w.subject) == "containment":
                gw.revoke(w.wid, reason="containment complete — drop the privilege")
        yield self._frame("WRAP-UP", "Containment is done. Its warrant is revoked.",
                          "REVOKE", "gold", "containment · net.isolate revoked")

        d = gw.enforce(ToolCall(agent=c_id, action="net.isolate", target="host-9"))
        yield self._frame("WRAP-UP", "Containment tries one more isolate — cut off at the gateway.",
                          d.verdict, "deny", "containment · net.isolate(host-9)", d.reason)

        # 6 ─ TTL EXPIRY: time passes; the third party's grant lapses on its own.
        self.clock.tick(121)
        d = gw.enforce(ToolCall(agent=i_id, action="intel.lookup", target="1.1.1.1"))
        yield self._frame("WRAP-UP", "121s later, the intel grant has expired — no revoke needed.",
                          d.verdict, "deny", "threat-intel · intel.lookup(1.1.1.1)", d.reason)


def play() -> tuple[Gateway, list[Frame]]:
    """Run the replay and return the gateway plus all frames (verdicts are real)."""
    room = WarRoom()
    return room.gateway, list(room.play())
