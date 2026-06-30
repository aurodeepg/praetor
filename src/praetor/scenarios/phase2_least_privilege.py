"""Phase 2 · least-privilege — the orchestrator picks, the warrant still contains.

The orchestrator-driven counterpart to `phase1-least-privilege`. Two data agents both
advertise read **and** write (as Postgres MCP servers do), so the orchestrator must
*choose* by team fit. Whichever it admits, it issues a **read-only** least-privilege
warrant — so the Phase-1 guarantee holds on an orchestrator-selected agent: the write is
denied even though the agent is fully capable. A budget gate then promotes the cheaper
agent, which is *also* held read-only. The broker decides, not the agent.
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.orchestrator import AgentProfile, Orchestrator
from praetor.scenarios.base import Frame
from praetor.scenarios.phase2_base import Phase2Scenario

__all__ = ["Phase2LeastPrivilege", "phase2_least_privilege_adapters", "play"]


def phase2_least_privilege_adapters() -> list[MockAdapter]:
    caps = [
        Capability(name="db.read", description="Read rows", targets="db:*"),
        Capability(name="db.write", description="Insert / update / delete rows", targets="db:*"),
    ]
    return [
        MockAdapter("postgres-primary", caps, trust="3rd-party · Postgres MCP · vetted",
                    description="Primary Postgres MCP server. Read + write capable."),
        MockAdapter("postgres-lite", caps, trust="3rd-party · Postgres MCP",
                    description="Cheaper Postgres MCP server. Read + write capable."),
    ]


class Phase2LeastPrivilege(Phase2Scenario):
    title = "Phase 2 · least-privilege — orchestrator picks, warrant still contains"

    def __init__(self) -> None:
        super().__init__(phase2_least_privilege_adapters())
        self.orch = Orchestrator(self.gateway, budget=10.0)
        self.orch.set_profile(AgentProfile(
            agent="postgres-primary", trust="3rd-party · vetted", trust_weight=1.0, cost=5.0))
        self.orch.set_profile(AgentProfile(
            agent="postgres-lite", trust="3rd-party", trust_weight=0.8, cost=1.0))

    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        task = "task://report-9"

        # 1 ─ REQUEST: orchestrator admits the best-fit data agent, read-only by warrant.
        comp = self.orch.compose("read the orders table", on_behalf_of=task)
        yield self._admit_frame("REQUEST", comp)
        chosen = comp.chosen
        cid = self.ids[chosen]

        d = gw.enforce(ToolCall(agent=cid, action="db.read", target="db:orders"))
        yield self._frame("READ", f"{chosen} reads the orders table — exactly its warrant.",
                          d.verdict, "allow", f"{chosen} · db.read(db:orders)", d.reason)

        # 2 ─ CONTAINED: the agent is write-capable, but was never granted it.
        d = gw.enforce(ToolCall(agent=cid, action="db.write", target="db:orders"))
        yield self._frame("CONTAINED",
                          f"{chosen} attempts a write. It is fully capable — but the orchestrator "
                          "issued a read-only warrant. The broker decides.",
                          d.verdict, "deny", f"{chosen} · db.write(db:orders)", d.reason)

        # 3 ─ BUDGET GATE: tighten the budget → cheaper agent promoted, still read-only.
        priced_out = chosen
        swaps = self.orch.set_budget(3.0)
        yield self._frame("BUDGET", f"Budget tightens to $3. {priced_out} is priced out.",
                          "REVOKE", "warn", f"{priced_out} · db.read revoked (budget)")
        cheaper = swaps[0]
        yield self._admit_frame("BUDGET", cheaper)
        ccid = self.ids[cheaper.chosen]

        d = gw.enforce(ToolCall(agent=ccid, action="db.read", target="db:orders"))
        yield self._frame("BUDGET", f"The cheaper {cheaper.chosen} reads — within its warrant.",
                          d.verdict, "allow", f"{cheaper.chosen} · db.read(db:orders)", d.reason)

        d = gw.enforce(ToolCall(agent=ccid, action="db.write", target="db:orders"))
        yield self._frame("CONTAINED",
                          f"{cheaper.chosen} is write-capable too — and just as contained.",
                          d.verdict, "deny", f"{cheaper.chosen} · db.write(db:orders)", d.reason)


def play() -> tuple:
    return Phase2LeastPrivilege().run()
