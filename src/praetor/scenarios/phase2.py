"""Scenario — Phase 2: the team reshapes *itself*.

Where a Phase-1 replay would hand-script every team change, this one hands the
decisions to the **orchestrator**: it scores team fit (capability × trust × budget ×
availability), admits the best-fit agent, and recomposes on its own when an agent
underperforms or the budget tightens. The gateway still produces every allow/deny; the
orchestrator decides *who is on the team*.

Two beats straight from the public vision:
  • "an agent underperforms and gets swapped"
  • "a budget gate promotes a cheaper specialist"
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.orchestrator import AgentProfile, Composition, Orchestrator
from praetor.scenarios.base import Frame, Scenario

__all__ = ["Phase2", "phase2_adapters", "play"]


def phase2_adapters() -> list[MockAdapter]:
    isolate = Capability(name="net.isolate", description="Quarantine a host", targets="host:*")
    readlogs = Capability(name="logs.read", description="Read system and application logs",
                          targets="logs:*")
    return [
        MockAdapter("containment-a", [isolate], trust="internal · high-priv",
                    description="Primary containment agent."),
        MockAdapter("containment-b", [isolate], trust="internal · high-priv",
                    description="Backup containment agent."),
        MockAdapter("forensics-pro", [readlogs], trust="internal · vetted",
                    description="Deep forensics. Trusted, but expensive."),
        MockAdapter("forensics-lite", [readlogs], trust="internal",
                    description="Lightweight forensics. Cheap."),
    ]


class Phase2(Scenario):
    title = "Phase 2 — the team reshapes itself (orchestrator-driven)"

    def __init__(self) -> None:
        super().__init__(phase2_adapters())
        self.orch = Orchestrator(self.gateway, budget=10.0)
        for p in (
            AgentProfile(agent="containment-a", trust="internal · high-priv", cost=1.0),
            AgentProfile(agent="containment-b", trust="internal · high-priv", cost=2.0),
            AgentProfile(agent="forensics-pro", trust="internal · vetted",
                         trust_weight=1.0, cost=5.0),
            AgentProfile(agent="forensics-lite", trust="internal",
                         trust_weight=0.8, cost=1.0),
        ):
            self.orch.set_profile(p)

    def _admit_frame(self, phase: str, comp: Composition, cls: str = "gold") -> Frame:
        f = comp.fit
        return self._frame(
            phase,
            f"Orchestrator scores team fit and admits {comp.chosen} "
            f"(fit {f.score:.3f} = cap {f.capability_match:.2f} × trust {f.trust:.2f} "
            f"× budget {f.budget:.0f} × avail {f.availability:.0f}).",
            "ISSUE", cls, f"warrant issued · {comp.chosen} · {f.capability}", f.rationale)

    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        inc = "incident://ir-6102"

        # 1 ─ CONTAIN: orchestrator picks the best-fit containment agent.
        comp = self.orch.compose("isolate the compromised host host-9", on_behalf_of=inc)
        yield self._admit_frame("CONTAIN", comp)

        a_id = self.ids[comp.chosen]
        d = gw.enforce(ToolCall(agent=a_id, action="net.isolate", target="host-9"))
        yield self._frame("CONTAIN", f"{comp.chosen} isolates the host.",
                          d.verdict, "allow", f"{comp.chosen} · net.isolate(host-9)", d.reason)

        # 2 ─ UNDERPERFORM → SWAP: the orchestrator benches it and promotes the next best.
        dropped = comp.chosen
        swaps = self.orch.report_performance(dropped, ok=False)
        yield self._frame("EVOLVE", f"{dropped} underperforms. The orchestrator benches it.",
                          "REVOKE", "warn", f"{dropped} · net.isolate revoked (perf)")

        d = gw.enforce(ToolCall(agent=self.ids[dropped], action="net.isolate", target="host-9"))
        yield self._frame("EVOLVE", f"The benched {dropped} tries to act — cut off at the gateway.",
                          d.verdict, "deny", f"{dropped} · net.isolate(host-9)", d.reason)

        promoted = swaps[0]
        yield self._admit_frame("EVOLVE", promoted)
        p_id = self.ids[promoted.chosen]
        d = gw.enforce(ToolCall(agent=p_id, action="net.isolate", target="host-9"))
        yield self._frame("EVOLVE", f"The promoted {promoted.chosen} takes over the containment.",
                          d.verdict, "allow", f"{promoted.chosen} · net.isolate(host-9)", d.reason)

        # 3 ─ FORENSICS: with budget headroom, the trusted (pricier) specialist wins.
        fcomp = self.orch.compose("read the auth logs for the intrusion", on_behalf_of=inc)
        yield self._admit_frame("FORENSICS", fcomp, cls="info")
        f_id = self.ids[fcomp.chosen]
        d = gw.enforce(ToolCall(agent=f_id, action="logs.read", target="logs:auth-1"))
        yield self._frame("FORENSICS", f"{fcomp.chosen} reads the logs.",
                          d.verdict, "allow", f"{fcomp.chosen} · logs.read(logs:auth-1)", d.reason)

        # 4 ─ BUDGET GATE: tighten the budget; a cheaper specialist clears the bar.
        priced_out = fcomp.chosen
        bswaps = self.orch.set_budget(3.0)
        yield self._frame("BUDGET", f"Budget tightens to $3. {priced_out} is priced out.",
                          "REVOKE", "warn", f"{priced_out} · logs.read revoked (budget)")
        cheaper = bswaps[0]
        yield self._admit_frame("BUDGET", cheaper)
        c_id = self.ids[cheaper.chosen]
        d = gw.enforce(ToolCall(agent=c_id, action="logs.read", target="logs:auth-1"))
        yield self._frame("BUDGET", f"The cheaper {cheaper.chosen} continues the forensics.",
                          d.verdict, "allow",
                          f"{cheaper.chosen} · logs.read(logs:auth-1)", d.reason)


def play() -> tuple:
    return Phase2().run()
