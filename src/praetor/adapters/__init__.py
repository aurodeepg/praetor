"""Agent adapters — the bring-your-own-agent shim layer.

M5 ships the contract (`AgentAdapter`) and an in-process `MockAdapter`. Real adapters
(HTTP, MCP, Anthropic/Claude Cowork, OpenAI, Gemini, Copilot Studio) follow the same
two-method contract and arrive in a later milestone.
"""

from praetor.adapters.base import AgentAdapter
from praetor.adapters.mock import MockAdapter

__all__ = ["AgentAdapter", "MockAdapter"]
