"""The adapter contract — how *any* agent plugs into Praetor.

Praetor governs agents it doesn't own. An adapter is the thin shim that makes a
custom agent (MCP / your own framework) or a third-party agent (Claude Cowork,
ChatGPT, Gemini) look identical to the gateway. It does two things:

1. ``manifest()`` — advertise what the agent can do, to the capability registry.
2. ``invoke()``   — execute a call the gateway has **already authorized**.

Adapters never make authorization decisions. The gateway enforces the warrant
*before* ``invoke`` is ever called, so an adapter only ever runs work the agent is
currently allowed to do. Writing a new adapter for a new framework is just these two
methods.
"""

from __future__ import annotations

import abc

from praetor.models import CapabilityManifest, ToolCall, ToolResult


class AgentAdapter(abc.ABC):
    """Uniform wrapper around one agent, whoever built it and wherever it runs."""

    #: Stable agent name (used as the registry key and warrant subject name).
    name: str
    #: Trust label surfaced to the gateway, e.g. "internal", "3rd-party · prob.".
    trust: str = "unverified"

    @abc.abstractmethod
    def manifest(self) -> CapabilityManifest:
        """What this agent advertises it can do."""

    @abc.abstractmethod
    def invoke(self, call: ToolCall) -> ToolResult:
        """Execute an already-authorized call and return its result."""
