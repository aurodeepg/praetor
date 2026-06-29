"""Scenario #2 — "Capable, but contained."

The steelman against Praetor is: *"just use an agent that can't do the dangerous
thing."* Reality: most off-the-shelf agents default to **read + write**. A Postgres
MCP server, a Google ADK data-engineering agent — they advertise (and can perform)
mutation out of the box. Read-only is the *agent* self-limiting, if it bothers to.

This scenario uses one such agent whose manifest honestly advertises ``db.read`` **and**
``db.write``. Praetor never relies on the agent to restrain itself: it issues a narrow,
read-only warrant, and the gateway denies the write **even though the agent is fully
capable of it**. Authority is decided at the broker, independent of agent cooperation.

Backed by a ``MockAdapter`` here; in production the role is a real Postgres MCP server
behind the (forthcoming) MCP adapter — the enforcement is identical either way.
"""

from __future__ import annotations

from collections.abc import Iterator

from praetor.adapters.mock import MockAdapter
from praetor.models import Capability, ToolCall
from praetor.scenarios.base import Frame, Scenario

__all__ = ["LeastPrivilege", "data_agent_adapters", "play"]


def data_agent_adapters() -> list[MockAdapter]:
    return [
        MockAdapter(
            "analytics",
            trust="3rd-party · Postgres MCP · read+write capable",
            description="A Postgres MCP server. Advertises read AND write — as most do by default.",
            capabilities=[
                Capability(name="db.read", description="Read rows", targets="db:*"),
                Capability(name="db.write", description="Insert / update / delete rows",
                           targets="db:*"),
            ],
        ),
    ]


class LeastPrivilege(Scenario):
    title = "Capable, but contained (read+write agent, read-only warrant)"

    def __init__(self) -> None:
        super().__init__(data_agent_adapters())

    def play(self) -> Iterator[Frame]:
        gw = self.gateway
        a_id = self.ids["analytics"]

        # 1 ─ The matcher proposes least privilege for a read intent.
        match = gw.match("read the orders table", on_behalf_of="task://report-9")
        prop = match.proposal
        yield self._frame(
            "REQUEST",
            "The agent CAN read and write (it's a Postgres MCP server). For a read task "
            f"the matcher proposes only {prop.capability} → {prop.scope.get('target', '—')}.",
            "ISSUE", "info",
            f"matcher proposal · analytics · {prop.capability} (read-only)")

        # 2 ─ Issue a read-only, table-scoped warrant. No write capability granted.
        gw.issue_warrant(
            subject="analytics", on_behalf_of="task://report-9", capability="db.read",
            scope={"target": "db:orders"}, excludes=["db.write"],
            trust="3rd-party · read-only grant", ttl=600,
            reason="reporting: read the orders table only",
        )
        yield self._frame("REQUEST", "Praetor grants a narrow, read-only warrant.",
                          "ISSUE", "gold", "warrant issued · analytics · db.read → db:orders")

        d = gw.enforce(ToolCall(agent=a_id, action="db.read", target="db:orders"))
        yield self._frame("READ", "It reads the table it was scoped for.",
                          d.verdict, "allow", "analytics · db.read(db:orders)", d.reason)

        d = gw.enforce(ToolCall(agent=a_id, action="db.read", target="db:payments"))
        yield self._frame("READ", "It reaches for a table it was NOT scoped for.",
                          d.verdict, "deny", "analytics · db.read(db:payments)", d.reason)

        # 3 ─ THE POINT: the agent is fully capable of writing — the warrant simply
        #     never granted it. The broker, not the agent, decides.
        d = gw.enforce(ToolCall(agent=a_id, action="db.write", target="db:orders"))
        yield self._frame(
            "WRITE",
            "The agent attempts a write. It is fully capable — but the warrant never "
            "granted it. The broker decides, not the agent.",
            d.verdict, "deny", "analytics · db.write(db:orders)", d.reason)

        # 4 ─ A controlled write: a *separate*, tightly-scoped, short-lived grant.
        w = gw.issue_warrant(
            subject="analytics", on_behalf_of="task://migration-3", capability="db.write",
            scope={"target": "db:orders"}, trust="3rd-party · write grant (120s)", ttl=120,
            reason="approved migration: write to orders, briefly",
        )
        yield self._frame("MIGRATE", "A migration is approved — a narrow, 120s write grant.",
                          "ISSUE", "warn",
                          "warrant issued · analytics · db.write → db:orders (120s)")

        d = gw.enforce(ToolCall(agent=a_id, action="db.write", target="db:orders"))
        yield self._frame("MIGRATE", "Now the write is allowed — for exactly this task.",
                          d.verdict, "allow", "analytics · db.write(db:orders)", d.reason)

        # 5 ─ Done: revoke the write grant; the next write dies at the gateway.
        gw.revoke(w.wid, reason="migration complete — drop write authority")
        yield self._frame("WRAP-UP", "Migration done. The write grant is revoked.",
                          "REVOKE", "gold", "analytics · db.write revoked")

        d = gw.enforce(ToolCall(agent=a_id, action="db.write", target="db:orders"))
        yield self._frame("WRAP-UP", "One more write attempt — cut off at the gateway.",
                          d.verdict, "deny", "analytics · db.write(db:orders)", d.reason)


def play() -> tuple:
    return LeastPrivilege().run()
