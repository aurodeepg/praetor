"""Agent adapters — the bring-your-own-agent shim layer.

M5 ships the contract (`AgentAdapter`) and an in-process `MockAdapter`. M8 adds the
first *real* third-party adapter, `HTTPAdapter` (a remote agent over JSON). The rest
(MCP, Anthropic/Claude Cowork, OpenAI, Gemini, Copilot Studio) follow the same
two-method contract and arrive in later increments.

`HTTPAdapter` imports its optional dependency (`httpx`) lazily, so importing this
package never pulls in the `http`/provider extras.
"""

from praetor.adapters.base import AgentAdapter
from praetor.adapters.http import HTTPAdapter
from praetor.adapters.mock import MockAdapter

__all__ = ["AgentAdapter", "HTTPAdapter", "MockAdapter"]
