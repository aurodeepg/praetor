"""M8: the MCP adapter — govern any Model Context Protocol server.

The translation core (tools<->capabilities, CallToolResult<->ToolResult) and the
sync<->async bridge are tested against an injected fake session (no `mcp` needed). The
critical property — enforce-then-invoke — must hold for an MCP server too: a denied
call never reaches ``call_tool``.

A final block validates the translation against the *real* SDK types when `mcp` is
installed (skipped otherwise), so the mapping can't silently drift from the SDK.
"""

from types import SimpleNamespace

import pytest

from praetor.adapters import MCPAdapter
from praetor.adapters.mcp import _capabilities_from_tools, _to_tool_result
from praetor.gateway import Gateway
from praetor.models import ToolCall

TOOLS = [
    SimpleNamespace(name="net.isolate", description="Quarantine a host", inputSchema={}),
    SimpleNamespace(name="logs.read", description="Read logs", inputSchema={}),
]


class _FakeSession:
    """A duck-typed async MCP session: awaitable list_tools() / call_tool()."""

    def __init__(self, *, record: list | None = None, error: bool = False) -> None:
        self._record = record
        self._error = error

    async def list_tools(self):
        return SimpleNamespace(tools=TOOLS)

    async def call_tool(self, name, arguments):
        if self._record is not None:
            self._record.append((name, arguments))
        if self._error:
            return SimpleNamespace(
                isError=True, content=[SimpleNamespace(type="text", text="boom")]
            )
        return SimpleNamespace(
            isError=False,
            content=[SimpleNamespace(type="text", text=f"ran {name} on {arguments}")],
        )


# ── translation (pure) ───────────────────────────────────────────────────────


def test_tools_map_to_capabilities():
    caps = _capabilities_from_tools(TOOLS)
    assert [c.name for c in caps] == ["net.isolate", "logs.read"]
    assert caps[0].description == "Quarantine a host"
    assert caps[0].targets is None  # MCP tools carry no target glob


def test_call_tool_result_folds_to_tool_result():
    ok = SimpleNamespace(isError=False, content=[SimpleNamespace(type="text", text="42")])
    assert _to_tool_result(ok) == _to_tool_result(ok) and _to_tool_result(ok).output == "42"
    err = SimpleNamespace(isError=True, content=[SimpleNamespace(type="text", text="nope")])
    r = _to_tool_result(err)
    assert not r.ok and r.error == "nope"


# ── the contract over a (fake) MCP session ───────────────────────────────────


def test_manifest_is_built_from_list_tools():
    a = MCPAdapter("containment", _FakeSession())
    m = a.manifest()
    assert m.agent == "containment"
    assert [c.name for c in m.capabilities] == ["net.isolate", "logs.read"]
    a.close()


def test_invoke_relays_the_call_and_injects_target():
    record: list = []
    a = MCPAdapter("containment", _FakeSession(record=record))
    out = a.invoke(ToolCall(agent="x", action="net.isolate", target="host-9"))
    assert out.ok and "ran net.isolate" in out.output
    # the call's target is passed through to the MCP tool arguments
    assert record == [("net.isolate", {"target": "host-9"})]
    a.close()


def test_invoke_surfaces_a_tool_error_as_failed_result():
    a = MCPAdapter("containment", _FakeSession(error=True))
    out = a.invoke(ToolCall(agent="x", action="net.isolate", target="host-9"))
    assert not out.ok and out.error == "boom"
    a.close()


# ── the whole point: enforcement holds for an MCP server too ─────────────────


def test_gateway_governs_an_mcp_server_end_to_end():
    record: list = []
    gw = Gateway()
    ident = gw.register(MCPAdapter("containment", _FakeSession(record=record)))
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},
    )
    decision, result = gw.dispatch(
        ToolCall(agent=ident.id, action="net.isolate", target="host-9")
    )
    assert decision.allow and result.ok
    assert [name for name, _ in record] == ["net.isolate"]


def test_denied_call_never_reaches_call_tool():
    record: list = []
    gw = Gateway()
    ident = gw.register(MCPAdapter("containment", _FakeSession(record=record)))
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},  # scoped to host-9 only
    )
    decision, result = gw.dispatch(
        ToolCall(agent=ident.id, action="net.isolate", target="host-OTHER")
    )
    assert not decision.allow and result is None
    assert record == []  # call_tool was never reached


# ── validate the translation against the real SDK types (skip if absent) ─────


def test_translation_matches_real_mcp_sdk_types():
    pytest.importorskip("mcp")
    from mcp.types import CallToolResult, TextContent, Tool

    tools = [Tool(name="query", description="run sql", inputSchema={"type": "object"})]
    caps = _capabilities_from_tools(tools)
    assert caps[0].name == "query" and caps[0].description == "run sql"

    ok = CallToolResult(content=[TextContent(type="text", text="42")], isError=False)
    assert _to_tool_result(ok).ok and _to_tool_result(ok).output == "42"

    err = CallToolResult(content=[TextContent(type="text", text="bad")], isError=True)
    r = _to_tool_result(err)
    assert not r.ok and r.error == "bad"
