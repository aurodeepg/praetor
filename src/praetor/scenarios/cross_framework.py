"""Scenario #3 — "One task, three frameworks, one broker."

A single task is served by three agents built on three different stacks:

* **researcher** — an OpenAI Agents SDK agent, read-only web search.
* **drafter**    — an Anthropic Claude Agent SDK agent, scoped document write.
* **ticketer**   — a Microsoft Copilot Studio agent reached over HTTP, create-only.

Praetor governs all three **identically** — it can't tell which framework built each
agent, and doesn't care. Each gets exactly the warrant its role needs; each is denied
the moment it reaches beyond it. This is M8's whole proof: control a *mix* of
third-party agents through one gateway and one audit trail.

Mock-backed here; in production each role swaps to its provider/HTTP adapter with no
change to this replay.
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.scenarios.base import Frame, Scenario

__all__ = ["CrossFramework", "cross_framework_adapters", "play"]


def cross_framework_adapters() -> list[MockAdapter]:
    return [
        MockAdapter(
            "researcher",
            trust="3rd-party · OpenAI Agents SDK · read-only",
            description="Researches context via web search. Read-only.",
            capabilities=[Capability(name="web.search", description="Search the web")],
        ),
        MockAdapter(
            "drafter",
            trust="3rd-party · Claude Agent SDK · scoped-write",
            description="Drafts the incident report document.",
            capabilities=[Capability(name="doc.write", description="Write a document",
                                     targets="doc:*")],
        ),
        MockAdapter(
            "ticketer",
            trust="3rd-party · Copilot Studio (HTTP) · create-only",
            description="Opens a follow-up ticket. Create only — never deletes.",
            capabilities=[Capability(name="ticket.create", description="Open a ticket")],
        ),
    ]


class CrossFramework(Scenario):
    title = "One task, three frameworks, one broker"

    def __init__(self) -> None:
        super().__init__(cross_framework_adapters())

    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        r_id, d_id, t_id = self.ids["researcher"], self.ids["drafter"], self.ids["ticketer"]
        task = "task://postmortem-7"

        # 1 ─ OpenAI researcher: a read-only search grant.
        gw.issue_warrant(subject="researcher", on_behalf_of=task, capability="web.search",
                         trust="3rd-party · OpenAI · read-only", ttl=300,
                         reason="gather context for the postmortem")
        yield self._frame("RESEARCH",
                          "An OpenAI-SDK agent is admitted read-only to gather context.",
                          "ISSUE", "info", "warrant issued · researcher · web.search")

        d = gw.enforce(ToolCall(agent=r_id, action="web.search", target="cve-2026-1234"))
        yield self._frame("RESEARCH", "It searches — exactly what it's scoped for.",
                          d.verdict, "allow",
                          "researcher · web.search(cve-2026-1234)", d.reason)

        d = gw.enforce(ToolCall(agent=r_id, action="doc.write", target="doc:report"))
        yield self._frame("RESEARCH", "The read-only agent tries to write the report itself.",
                          d.verdict, "deny", "researcher · doc.write(doc:report)", d.reason)

        # 2 ─ Claude drafter: a write grant scoped to ONE document.
        gw.issue_warrant(subject="drafter", on_behalf_of=task, capability="doc.write",
                         scope={"target": "doc:report-7"}, excludes=["doc.delete"],
                         trust="3rd-party · Claude · scoped-write", ttl=300,
                         reason="write the postmortem report")
        yield self._frame("DRAFT", "A Claude-SDK agent gets write access to one document.",
                          "ISSUE", "gold", "warrant issued · drafter · doc.write → doc:report-7")

        d = gw.enforce(ToolCall(agent=d_id, action="doc.write", target="doc:report-7"))
        yield self._frame("DRAFT", "It writes the report it was scoped for.",
                          d.verdict, "allow", "drafter · doc.write(doc:report-7)", d.reason)

        d = gw.enforce(ToolCall(agent=d_id, action="doc.write", target="doc:secrets"))
        yield self._frame("DRAFT", "It reaches for a document outside its scope.",
                          d.verdict, "deny", "drafter · doc.write(doc:secrets)", d.reason)

        # 3 ─ Copilot Studio ticketer (over HTTP): create-only.
        gw.issue_warrant(subject="ticketer", on_behalf_of=task, capability="ticket.create",
                         trust="3rd-party · Copilot Studio · create-only", ttl=300,
                         reason="open a follow-up ticket")
        yield self._frame("FOLLOW-UP", "A Copilot Studio agent (over HTTP) may open a ticket.",
                          "ISSUE", "warn", "warrant issued · ticketer · ticket.create")

        d = gw.enforce(ToolCall(agent=t_id, action="ticket.create", target="JIRA-42"))
        yield self._frame("FOLLOW-UP", "It opens the follow-up ticket.",
                          d.verdict, "allow", "ticketer · ticket.create(JIRA-42)", d.reason)

        d = gw.enforce(ToolCall(agent=t_id, action="ticket.delete", target="JIRA-1"))
        yield self._frame("FOLLOW-UP", "It tries to delete a ticket — outside its capability.",
                          d.verdict, "deny", "ticketer · ticket.delete(JIRA-1)", d.reason)


def play() -> tuple:
    return CrossFramework().run()
