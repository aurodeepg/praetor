"""Agent adapters — the bring-your-own-agent shim layer.

M5 ships the contract (`AgentAdapter`) and an in-process `MockAdapter`. M8 adds the
real third-party adapters: `HTTPAdapter` (a remote agent over JSON) and `MCPAdapter`
(any Model Context Protocol server). The rest (Anthropic/Claude Cowork, OpenAI, Gemini,
Copilot Studio) follow the same two-method contract and arrive in later increments.

Each real adapter imports its optional dependency lazily (`httpx` for HTTP, `mcp` for
MCP), so importing this package never pulls in the `http`/`mcp`/provider extras.
"""

from praetor.adapters.base import AgentAdapter
from praetor.adapters.http import HTTPAdapter
from praetor.adapters.mcp import MCPAdapter
from praetor.adapters.mock import MockAdapter

__all__ = ["AgentAdapter", "HTTPAdapter", "MCPAdapter", "MockAdapter"]
