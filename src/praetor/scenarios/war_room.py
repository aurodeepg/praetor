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

from praetor.gateway import Gateway
from praetor.models import ToolCall
from praetor.scenarios.base import Frame, LedgerRow, Scenario
from praetor.scenarios.seed import war_room_adapters

__all__ = ["Frame", "LedgerRow", "WarRoom", "play"]


class WarRoom(Scenario):
    """Scenario #1 — the mixed-trust incident war room (the headline demo).

    Roster (each a real third-party agent in production; mock-backed here): a
    high-privilege **containment** agent, a read-only **forensics** agent, and an
    untrusted third-party **threat-intel** agent. The replay also exercises live
    revocation and TTL expiry (scenario #4's beats fold in here).
    """

    title = "Incident-response war room"

    def __init__(self) -> None:
        super().__init__(war_room_adapters())

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
