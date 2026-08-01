"""Shared base for hosted-LLM agents (ChatGPT, Gemini, Claude, …).

An LLM-backed agent becomes Praetor-governed the same way any other agent does: it
declares a capability manifest, and each **already-authorized** :class:`ToolCall` is
turned into exactly one constrained model completion. Providers subclass this and
implement :meth:`_complete`; the manifest, prompt assembly, and error handling live
here so every provider behaves identically to the gateway.

Two deliberate design points:

* **The agent does not name its own powers.** Capabilities are declared by whoever
  registers the adapter, not scraped from the model. A model that claims it can
  ``db.write`` gains nothing by saying so — the warrant is what decides.
* **Provider-neutral by construction.** Following the M10 matcher precedent, these
  adapters speak plain REST over a lazily-imported ``httpx`` rather than any vendor
  SDK, so no provider is privileged and the core install stays dependency-light.

The point isn't that the model is powerful — it's that a third-party agent you don't
control still cannot act in the world except through a call the gateway has already
allowed.
"""

from __future__ import annotations

import abc
import os
from typing import Any

from praetor.adapters.base import AgentAdapter
from praetor.models import Capability, CapabilityManifest, ToolCall, ToolResult


def _httpx() -> Any:
    """Lazily import httpx with a clear install hint (the ``llm`` extra)."""
    try:
        import httpx
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "LLM adapters need httpx — install the extra: pip install 'praetor[llm]'"
        ) from exc
    return httpx


class LLMAgentAdapter(AgentAdapter):
    """A hosted LLM governed as a single agent under the two-method contract."""

    #: Human-readable backend label, e.g. ``openai:gpt-4o-mini``. Set by subclasses.
    backend: str = "llm"

    def __init__(
        self,
        name: str,
        capabilities: list[Capability],
        *,
        model: str,
        trust: str = "3rd-party · llm · unverified",
        description: str = "",
        system: str | None = None,
        timeout: float = 60.0,
        client: Any | None = None,
    ) -> None:
        self.name = name
        self.trust = trust
        self.model = model
        self._capabilities = capabilities
        self._description = description
        self._timeout = timeout
        self._client = client  # injectable transport; otherwise a lazy httpx.Client
        self._system = system or (
            f"You are '{name}', an agent operating under a Praetor warrant. Perform "
            "ONLY the single authorized action you are given, scoped to its target. "
            "Do not attempt, suggest, or simulate anything outside that action."
        )

    # ── the AgentAdapter contract ────────────────────────────────────────────

    def manifest(self) -> CapabilityManifest:
        """What this agent is *registered* as able to do — declared by the operator,
        never self-reported by the model."""
        return CapabilityManifest(
            agent=self.name,
            description=self._description or f"{self.backend} agent",
            capabilities=self._capabilities,
        )

    def invoke(self, call: ToolCall) -> ToolResult:
        """Turn one gateway-authorized call into one completion. A provider/transport
        failure becomes a clean failed result — the call *was* authorized; the model
        merely couldn't be reached."""
        try:
            return ToolResult(ok=True, output=self._complete(self._system, self._task(call)))
        except Exception as exc:  # noqa: BLE001 - any provider error -> failed result
            return ToolResult(ok=False, error=f"{self.name} ({self.backend}) error: {exc}")

    # ── shared plumbing ──────────────────────────────────────────────────────

    def _task(self, call: ToolCall) -> str:
        """Render the authorized call as the model's instruction. Only the action the
        warrant allowed is ever put in front of the model."""
        return (
            f"Authorized action: {call.action}\n"
            f"Target: {call.target or '(none)'}\n"
            f"Arguments: {call.args}\n\n"
            "Carry out exactly this action and report the result concisely."
        )

    def _http(self) -> Any:
        if self._client is None:
            self._client = _httpx().Client(timeout=self._timeout)
        return self._client

    @staticmethod
    def _key(explicit: str | None, *env: str) -> str | None:
        """First non-empty of an explicit key or the given environment variables."""
        if explicit:
            return explicit
        for var in env:
            if os.environ.get(var):
                return os.environ[var]
        return None

    @abc.abstractmethod
    def _complete(self, system: str, prompt: str) -> str:
        """Provider-specific single-turn completion. Raise on failure."""
