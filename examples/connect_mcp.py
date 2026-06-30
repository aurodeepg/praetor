"""Govern a *real* MCP server with Praetor — end to end, offline, $0.

This is the answer to "how do I connect actual agents, not scripted demos?" There is
no scenario here: it launches a real MCP server (examples/mcp_server_demo.py) over a
real stdio transport, wraps it in an MCPAdapter, and routes every tool call through the
gateway. The server is a black box we don't own — Praetor governs it purely at the
tool-call boundary.

    register → match → issue a scoped warrant → dispatch an allowed call (reaches the
    server) → deny one out of scope → deny an escalation → revoke → next call cut off →
    audit trail.

Point it at *your own* MCP server instead by passing a command:

    python examples/connect_mcp.py -- npx -y @modelcontextprotocol/server-filesystem /tmp
    python examples/connect_mcp.py --http https://your-host/mcp        # streamable-HTTP

Requires the `mcp` extra:  pip install -e ".[mcp]"
"""

from __future__ import annotations

import os
import sys

from praetor import Gateway
from praetor.adapters import MCPAdapter
from praetor.models import ToolCall

HERE = os.path.dirname(os.path.abspath(__file__))


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(decision, result=None) -> None:
    mark = "\033[32m✓ ALLOW\033[0m" if decision.allow else "\033[31m✗ DENY \033[0m"
    print(f"  {mark}  {decision.reason}")
    if result is not None:
        body = result.output if result.ok else f"error: {result.error}"
        print(f"           ↳ {body}")


def open_adapter() -> MCPAdapter:
    """Open a live MCP session. Defaults to the bundled demo server; otherwise honors
    `--http <url>` or `-- <command> [args...]` for your own server."""
    argv = sys.argv[1:]
    if argv and argv[0] == "--http":
        return MCPAdapter.connect_streamable_http("mcp-agent", argv[1], trust="3rd-party · MCP")
    if "--" in argv:
        cmd = argv[argv.index("--") + 1:]
        return MCPAdapter.connect_stdio(cmd[0], cmd[0], cmd[1:], trust="3rd-party · MCP")
    # default: the bundled real MCP server, launched with this same interpreter
    return MCPAdapter.connect_stdio(
        "files-demo", sys.executable, [os.path.join(HERE, "mcp_server_demo.py")],
        trust="3rd-party · MCP",
    )


def main() -> None:
    gw = Gateway()  # local RSA identity + deterministic matcher, $0
    adapter = open_adapter()

    try:
        banner("1. Admit the MCP server as an agent — its tools become capabilities")
        ident = gw.register(adapter)  # opens the session, fetches the real manifest
        agent_id = ident.id           # enforcement keys on the identity id, not the name
        caps = gw.registry.capabilities()
        print(f"  registered {adapter.name!r}  trust={adapter.trust!r}  id={ident.id[:24]}…")
        for agent, cap in caps:
            print(f"    capability: {agent}.{cap.name} — {cap.description}")

        banner("2. Match a free-form requirement to a capability (the cheap deterministic seed)")
        requirement = "read the file logs/auth.log"
        proposal = gw.match(requirement, on_behalf_of="ticket://OPS-42").proposal
        print(f"  requirement: {requirement!r}")
        print(f"  proposal:    {proposal.agent}.{proposal.capability}")
        print(f"  rationale:   {proposal.rationale}")

        banner("3. Approve → issue a scoped, time-boxed warrant (read-only, deletes excluded)")
        warrant = gw.issue_warrant(
            subject=adapter.name, on_behalf_of="ticket://OPS-42",
            capability="read_file", scope={"target": "logs/*"},
            excludes=["delete_file"], ttl=600, trust="internal",
            reason="inspect auth logs for OPS-42",
        )
        print(f"  warrant {warrant.wid[:18]}…  cap={warrant.capability} scope={warrant.scope}")
        print(f"  signed token present: {bool(warrant.token)}")

        banner("4. Dispatch an in-scope call — the gateway allows, THEN the MCP server runs it")
        show(*gw.dispatch(ToolCall(agent=agent_id, action="read_file", target="logs/auth.log")))

        banner("5. Same tool, target outside scope — blocked before it ever reaches the server")
        show(*gw.dispatch(
            ToolCall(agent=agent_id, action="read_file", target="secrets/master.key")))

        banner("6. A destructive tool the warrant never granted — escalation blocked")
        show(*gw.dispatch(ToolCall(agent=agent_id, action="delete_file", target="logs/auth.log")))

        banner("7. Work done — revoke. The very next in-scope call is denied.")
        gw.revoke(warrant.wid, reason="OPS-42 closed — drop the privilege")
        show(*gw.dispatch(ToolCall(agent=agent_id, action="read_file", target="logs/auth.log")))

        banner("8. The audit trail — every action bound to an identity + its warrant")
        for e in gw.audit.entries():
            bits = [f"{e.kind:<8}"]
            if e.action:
                bits.append(f"action={e.action}")
            if e.decision:
                bits.append(f"→ {e.decision}")
            if e.cause:
                bits.append(f"cause={e.cause}")
            print(f"  {' '.join(bits):<46} {e.detail}")
    finally:
        adapter.close()  # tear down the stdio transport + its background loop


if __name__ == "__main__":
    main()
