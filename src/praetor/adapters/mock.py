"""In-process mock agent — for tests and the deterministic war-room demo.

Carries a fixed manifest and either canned outputs or per-action handlers. No
network, no model, fully deterministic — the reference implementation of the adapter
contract that real third-party adapters (HTTP, MCP, Anthropic, …) follow.
"""

from __future__ import annotations

from collections.abc import Callable

from praetor.adapters.base import AgentAdapter
from praetor.models import Capability, CapabilityManifest, ToolCall, ToolResult

Handler = Callable[[ToolCall], ToolResult]


class MockAdapter(AgentAdapter):
    def __init__(
        self,
        name: str,
        capabilities: list[Capability],
        *,
        trust: str = "internal",
        description: str = "",
        handlers: dict[str, Handler] | None = None,
    ) -> None:
        self.name = name
        self.trust = trust
        self._description = description
        self._capabilities = capabilities
        self._handlers = handlers or {}

    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            agent=self.name,
            description=self._description,
            capabilities=self._capabilities,
        )

    def invoke(self, call: ToolCall) -> ToolResult:
        handler = self._handlers.get(call.action)
        if handler:
            return handler(call)
        return ToolResult(
            ok=True, output=f"{self.name} executed {call.action}({call.target or ''})"
        )
