"""Agent adapters — the bring-your-own-agent shim layer.

M5 ships the contract (`AgentAdapter`) and an in-process `MockAdapter`. M8 adds the
real third-party adapters: `HTTPAdapter` (a remote agent over JSON), `MCPAdapter` (any
Model Context Protocol server), and the hosted-LLM family built on `LLMAgentAdapter`
(`OpenAIAdapter` and, in following increments, Gemini / Anthropic / Copilot Studio).

Every one of them is a dumb conduit: the gateway enforces the warrant *before* `invoke`,
so no adapter ever makes an authorization decision. Optional dependencies are imported
lazily (`httpx` for HTTP and the LLM family, `mcp` for MCP), so importing this package
never pulls in the `http`/`mcp`/`llm` extras.
"""

from praetor.adapters.base import AgentAdapter
from praetor.adapters.http import HTTPAdapter
from praetor.adapters.llm import LLMAgentAdapter
from praetor.adapters.mcp import MCPAdapter
from praetor.adapters.mock import MockAdapter
from praetor.adapters.openai import OpenAIAdapter

__all__ = [
    "AgentAdapter",
    "HTTPAdapter",
    "LLMAgentAdapter",
    "MCPAdapter",
    "MockAdapter",
    "OpenAIAdapter",
]
