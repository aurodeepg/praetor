"""MCP adapter — govern any Model Context Protocol server as a Praetor agent.

This is the highest-leverage third-party adapter: MCP's own primitives map ~1:1 onto
our contract, so one adapter unlocks the entire MCP ecosystem (thousands of servers).

    MCP `list_tools()`            ->  manifest()  (each tool becomes a Capability)
    MCP `call_tool(name, args)`   ->  invoke()    (CallToolResult becomes a ToolResult)

Like every adapter, this is a **dumb conduit** with no authorization logic. The gateway
decides ALLOW *before* :meth:`invoke`, so a denied call never reaches ``call_tool`` and
never crosses to the MCP server. An MCP server is a governed *tool surface*, not an
autonomous agent — Praetor sits exactly at the tool-call boundary.

MCP is async-first; the :class:`AgentAdapter` contract is synchronous. We bridge with a
dedicated background event loop so the session lives on one consistent loop across the
sync boundary. The translation core (tools<->capabilities, result<->result) is fully
unit-tested against an injected session; the live transports (`connect_*`) require the
``mcp`` extra and a reachable server, and are lazily imported.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from praetor.adapters.base import AgentAdapter
from praetor.models import Capability, CapabilityManifest, ToolCall, ToolResult


class _Loop:
    """A background event loop on its own thread, so synchronous adapter methods can
    drive an async MCP session that stays bound to a single loop."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def run(self, coro: Any, timeout: float | None = None) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)


def _capabilities_from_tools(tools: list[Any]) -> list[Capability]:
    """Map MCP ``Tool`` objects to advertised capabilities. MCP tools carry no target
    glob, so ``targets`` stays unconstrained here — a warrant still scopes by target."""
    return [
        Capability(name=t.name, description=(getattr(t, "description", "") or ""))
        for t in tools
    ]


def _to_tool_result(result: Any) -> ToolResult:
    """Fold an MCP ``CallToolResult`` (content blocks + ``isError``) into a ToolResult."""
    blocks = getattr(result, "content", None) or []
    text = "".join(
        getattr(b, "text", "") for b in blocks if getattr(b, "type", None) == "text"
    )
    if getattr(result, "isError", False):
        return ToolResult(ok=False, error=text or "MCP tool reported an error")
    return ToolResult(ok=True, output=text)


class MCPAdapter(AgentAdapter):
    """Wrap one MCP server so it looks identical to any other Praetor agent.

    Construct directly with an already-open async ``session`` (duck-typed: it needs
    awaitable ``list_tools()`` and ``call_tool(name, arguments)``), or use one of the
    ``connect_*`` classmethods to open a live session over a real transport.
    """

    def __init__(
        self,
        name: str,
        session: Any,
        *,
        trust: str = "3rd-party · MCP · unverified",
        description: str = "",
        loop: _Loop | None = None,
        timeout: float = 30.0,
        target_arg: str = "target",
    ) -> None:
        self.name = name
        self.trust = trust
        self._description = description
        self._session = session
        self._timeout = timeout
        self._target_arg = target_arg
        self._loop = loop or _Loop()
        self._owns_loop = loop is None
        self._stack: Any | None = None  # set by connect_* to own the transport lifecycle

    def manifest(self) -> CapabilityManifest:
        tools = self._loop.run(self._session.list_tools(), self._timeout).tools
        return CapabilityManifest(
            agent=self.name,
            description=self._description,
            capabilities=_capabilities_from_tools(tools),
        )

    def invoke(self, call: ToolCall) -> ToolResult:
        """Relay an already-authorized call to the MCP server. The gateway decided ALLOW
        before we got here; any transport/timeout failure becomes a clean failed result."""
        arguments = dict(call.args)
        if call.target is not None:
            arguments.setdefault(self._target_arg, call.target)
        try:
            result = self._loop.run(
                self._session.call_tool(call.action, arguments), self._timeout
            )
        except FutureTimeout:
            return ToolResult(ok=False, error=f"{self.name} MCP call timed out")
        except Exception as exc:  # noqa: BLE001 - any MCP/transport error -> failed result
            return ToolResult(ok=False, error=f"{self.name} MCP error: {exc}")
        return _to_tool_result(result)

    def close(self) -> None:
        """Tear down the transport (if we opened one) and the background loop (if ours)."""
        if self._stack is not None:
            try:
                self._loop.run(self._stack.aclose(), self._timeout)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            self._stack = None
        if self._owns_loop:
            self._loop.close()

    # ── live transports (need the `mcp` extra + a reachable server) ──────────────
    @classmethod
    def connect_streamable_http(
        cls, name: str, url: str, *, headers: dict[str, str] | None = None, **kw: Any
    ) -> MCPAdapter:
        """Open a session against a streamable-HTTP MCP server (hosted servers, and
        local ones run with an HTTP transport). Requires ``pip install 'praetor[mcp]'``."""
        loop = _Loop()

        async def _open() -> tuple[Any, Any]:
            from contextlib import AsyncExitStack

            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client

            stack = AsyncExitStack()
            read, write, _ = await stack.enter_async_context(
                streamablehttp_client(url, headers=headers)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            return session, stack

        session, stack = loop.run(_open())
        adapter = cls(name, session, loop=loop, **kw)
        adapter._stack = stack
        return adapter

    @classmethod
    def connect_stdio(
        cls, name: str, command: str, args: list[str] | None = None, **kw: Any
    ) -> MCPAdapter:
        """Open a session against a stdio MCP server (the common ``npx``/binary servers).
        Requires ``pip install 'praetor[mcp]'`` and the server command on PATH."""
        loop = _Loop()

        async def _open() -> tuple[Any, Any]:
            from contextlib import AsyncExitStack

            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client

            stack = AsyncExitStack()
            params = StdioServerParameters(command=command, args=args or [])
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            return session, stack

        session, stack = loop.run(_open())
        adapter = cls(name, session, loop=loop, **kw)
        adapter._stack = stack
        return adapter
