"""Phase 2 · cross-framework — the orchestrator picks the best-fit agent per subtask.

The orchestrator-driven counterpart to `phase1-cross-framework`. A single incident is
served by agents from different stacks (OpenAI, Claude, Copilot Studio). For each
subtask the orchestrator scores team fit and admits the best agent — and when the
chosen researcher underperforms, it swaps to the rival framework's agent. Every agent
is still governed identically and contained by its warrant; only the *selection* is
intelligent.
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.orchestrator import AgentProfile, Orchestrator
from praetor.scenarios.base import Frame
from praetor.scenarios.phase2_base import Phase2Scenario

__all__ = ["Phase2CrossFramework", "phase2_cross_framework_adapters", "play"]


def phase2_cross_framework_adapters() -> list[MockAdapter]:
    search = Capability(name="web.search", description="Search the web")
    write = Capability(name="doc.write", description="Write a document", targets="doc:*")
    ticket = Capability(name="ticket.create", description="Open a ticket")
    return [
        MockAdapter("openai-researcher", [search], trust="3rd-party · OpenAI Agents SDK",
                    description="Researches context via web search."),
        MockAdapter("claude-researcher", [search], trust="3rd-party · Claude Agent SDK · vetted",
                    description="Researches context via web search."),
        MockAdapter("claude-drafter", [write], trust="3rd-party · Claude Agent SDK",
                    description="Drafts the incident report."),
        MockAdapter("copilot-ticketer", [ticket], trust="3rd-party · Copilot Studio (HTTP)",
                    description="Opens a follow-up ticket."),
    ]


class Phase2CrossFramework(Phase2Scenario):
    title = "Phase 2 · cross-framework — orchestrator picks the best-fit agent per subtask"

    def __init__(self) -> None:
        super().__init__(phase2_cross_framework_adapters())
        self.orch = Orchestrator(self.gateway)  # no budget ceiling here
        for name, weight in (
            ("openai-researcher", 0.8), ("claude-researcher", 1.0),
            ("claude-drafter", 0.9), ("copilot-ticketer", 0.7),
        ):
            self.orch.set_profile(AgentProfile(agent=name, trust="3rd-party", trust_weight=weight))

    def play(self) -> Iterator[Frame]:
        gw = self.gateway

        # 1 ─ RESEARCH: best-fit researcher across frameworks (Claude edges OpenAI on trust).
        rcomp = self.orch.compose("search the web for intelligence on cve-2026-1234",
                                  on_behalf_of="incident://pm-7/research")
        yield self._admit_frame("RESEARCH", rcomp, cls="info")
        d = gw.enforce(ToolCall(agent=self.ids[rcomp.chosen], action="web.search",
                                target="cve-2026-1234"))
        yield self._frame("RESEARCH", f"{rcomp.chosen} searches — within its warrant.",
                          d.verdict, "allow",
                          f"{rcomp.chosen} · web.search(cve-2026-1234)", d.reason)

        # 2 ─ SWAP: the chosen researcher underperforms → orchestrator promotes the rival.
        dropped = rcomp.chosen
        swaps = self.orch.report_performance(dropped, ok=False)
        yield self._frame("EVOLVE", f"{dropped} underperforms. The orchestrator benches it.",
                          "REVOKE", "warn", f"{dropped} · web.search revoked (perf)")
        d = gw.enforce(ToolCall(agent=self.ids[dropped], action="web.search",
                                target="cve-2026-1234"))
        yield self._frame("EVOLVE", f"The benched {dropped} is cut off at the gateway.",
                          d.verdict, "deny", f"{dropped} · web.search(cve-2026-1234)", d.reason)
        promoted = swaps[0]
        yield self._admit_frame("EVOLVE", promoted, cls="info")
        d = gw.enforce(ToolCall(agent=self.ids[promoted.chosen], action="web.search",
                                target="cve-2026-1234"))
        yield self._frame("EVOLVE", f"The rival-framework {promoted.chosen} takes over.",
                          d.verdict, "allow",
                          f"{promoted.chosen} · web.search(cve-2026-1234)", d.reason)

        # 3 ─ DRAFT: the Claude drafter gets a write grant scoped to one document.
        dcomp = self.orch.compose("write the postmortem report-7",
                                  on_behalf_of="incident://pm-7/draft")
        yield self._admit_frame("DRAFT", dcomp)
        did = self.ids[dcomp.chosen]
        d = gw.enforce(ToolCall(agent=did, action="doc.write", target="report-7"))
        yield self._frame("DRAFT", f"{dcomp.chosen} writes the report it was scoped for.",
                          d.verdict, "allow", f"{dcomp.chosen} · doc.write(report-7)", d.reason)
        d = gw.enforce(ToolCall(agent=did, action="doc.write", target="secrets-1"))
        yield self._frame("DRAFT", f"{dcomp.chosen} reaches for a document outside its scope.",
                          d.verdict, "deny", f"{dcomp.chosen} · doc.write(secrets-1)", d.reason)

        # 4 ─ FOLLOW-UP: the Copilot Studio ticketer may only create.
        tcomp = self.orch.compose("open a ticket ops-1",
                                  on_behalf_of="incident://pm-7/ticket")
        yield self._admit_frame("FOLLOW-UP", tcomp, cls="warn")
        tid = self.ids[tcomp.chosen]
        d = gw.enforce(ToolCall(agent=tid, action="ticket.create", target="ops-1"))
        yield self._frame("FOLLOW-UP", f"{tcomp.chosen} opens the follow-up ticket.",
                          d.verdict, "allow", f"{tcomp.chosen} · ticket.create(ops-1)", d.reason)
        d = gw.enforce(ToolCall(agent=tid, action="ticket.delete", target="ops-1"))
        yield self._frame("FOLLOW-UP",
                          f"{tcomp.chosen} tries to delete a ticket — outside capability.",
                          d.verdict, "deny", f"{tcomp.chosen} · ticket.delete(ops-1)", d.reason)


def play() -> tuple:
    return Phase2CrossFramework().run()
