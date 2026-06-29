"""Scenario #4 — "The team reshapes itself."

The core thesis made literal: **team membership *is* the set of currently-valid
warrants.** As an incident moves phase, the gateway recomposes the team by *revoking*
the warrants a phase no longer needs and *issuing* the ones the next phase does. No
agent is redeployed; authority is what changes.

Here: CONTAIN admits a high-privilege containment agent; the phase shifts to REMEDIATE,
so containment is dropped (revoke, cause ``phase``) and a remediation agent is admitted.
The audit trail shows the team's shape as an emergent property of evolving requirements.

This is the seam the Phase-2 orchestrator (M9) automates: today the phase change is
scripted; M9 makes the *decision* to revoke/issue itself.
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.scenarios.base import Frame, Scenario

__all__ = ["Recompose", "recompose_adapters", "play"]


def recompose_adapters() -> list[MockAdapter]:
    return [
        MockAdapter(
            "containment",
            trust="internal · high-priv",
            description="Isolates compromised hosts. Needed during CONTAIN only.",
            capabilities=[Capability(name="net.isolate", description="Quarantine a host",
                                     targets="host:*")],
        ),
        MockAdapter(
            "remediation",
            trust="internal · high-priv",
            description="Rolls back / redeploys services. Needed during REMEDIATE only.",
            capabilities=[Capability(name="deploy.rollback", description="Roll back a service",
                                     targets="svc:*")],
        ),
    ]


class Recompose(Scenario):
    title = "The team reshapes itself (phase-driven recomposition)"

    def __init__(self) -> None:
        super().__init__(recompose_adapters())

    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        c_id, r_id = self.ids["containment"], self.ids["remediation"]
        inc = "incident://ir-5009"

        # 1 ─ CONTAIN: only containment is on the team.
        gw.issue_warrant(subject="containment", on_behalf_of=inc, capability="net.isolate",
                         scope={"target": "host-9"}, trust="internal · high-priv", ttl=300,
                         reason="contain the compromised host")
        yield self._frame("CONTAIN", "Phase CONTAIN: a containment agent is admitted to the team.",
                          "ISSUE", "gold", "warrant issued · containment · net.isolate → host-9")

        d = gw.enforce(ToolCall(agent=c_id, action="net.isolate", target="host-9"))
        yield self._frame("CONTAIN", "Containment isolates the host.",
                          d.verdict, "allow", "containment · net.isolate(host-9)", d.reason)

        # 2 ─ PHASE SHIFT → REMEDIATE: drop containment, admit remediation.
        for w in gw.active_warrants():
            if self._name_of.get(w.subject) == "containment":
                gw.revoke(w.wid, cause="phase",
                          reason="phase → REMEDIATE: containment no longer needed")
        yield self._frame("REMEDIATE",
                          "Phase shifts to REMEDIATE. Containment is dropped from the team.",
                          "REVOKE", "warn", "containment · net.isolate revoked (phase)")

        gw.issue_warrant(subject="remediation", on_behalf_of=inc, capability="deploy.rollback",
                         scope={"target": "svc:web"}, trust="internal · high-priv", ttl=300,
                         reason="roll back the affected service")
        yield self._frame("REMEDIATE", "A remediation agent is admitted — the team has reshaped.",
                          "ISSUE", "gold",
                          "warrant issued · remediation · deploy.rollback → svc:web")

        # 3 ─ The dropped agent is now cut off; the new one acts within its scope.
        d = gw.enforce(ToolCall(agent=c_id, action="net.isolate", target="host-9"))
        yield self._frame("REMEDIATE", "Containment tries to act after being dropped — denied.",
                          d.verdict, "deny", "containment · net.isolate(host-9)", d.reason)

        d = gw.enforce(ToolCall(agent=r_id, action="deploy.rollback", target="svc:web"))
        yield self._frame("REMEDIATE", "Remediation rolls back the service it was scoped for.",
                          d.verdict, "allow", "remediation · deploy.rollback(svc:web)", d.reason)

        d = gw.enforce(ToolCall(agent=r_id, action="deploy.rollback", target="svc:payments"))
        yield self._frame("REMEDIATE", "It reaches for a service outside its scope — denied.",
                          d.verdict, "deny",
                          "remediation · deploy.rollback(svc:payments)", d.reason)


def play() -> tuple:
    return Recompose().run()
