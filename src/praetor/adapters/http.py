"""HTTP adapter — govern an agent that runs as a remote HTTP service.

The first *real* third-party adapter (M8). The agent lives behind two JSON endpoints
and Praetor never sees inside it:

    GET  {base_url}/manifest   -> CapabilityManifest JSON
    POST {base_url}/invoke     -> ToolResult JSON   (request body: a ToolCall)

Crucially, this adapter carries **no authorization logic** — it is a dumb conduit.
The gateway has already decided ALLOW *before* :meth:`invoke` is called, so the
remote agent only ever receives calls it is currently warranted for. An agent we
don't own and can't see inside is still fully governed, because every call it makes
to do real work flows through the gateway first.

``httpx`` is an optional dependency (the ``http`` extra) imported lazily, so the core
install stays dependency-light. Pass a pre-built ``client`` to inject a transport
(e.g. in tests) or to reuse a connection pool.
"""

from __future__ import annotations

from typing import Any

from praetor.adapters.base import AgentAdapter
from praetor.models import CapabilityManifest, ToolCall, ToolResult


class HTTPAdapter(AgentAdapter):
    """Wrap a remote HTTP agent so it looks identical to any in-process adapter."""

    def __init__(
        self,
        name: str,
        base_url: str,
        *,
        trust: str = "3rd-party · unverified",
        timeout: float = 10.0,
        client: Any | None = None,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.trust = trust
        self._timeout = timeout
        self._client = client  # injectable; otherwise a lazily-built httpx.Client

    def _http(self) -> Any:
        if self._client is None:
            try:
                import httpx
            except ModuleNotFoundError as exc:  # pragma: no cover - import guard
                raise RuntimeError(
                    "HTTPAdapter needs httpx — install the extra: pip install 'praetor[http]'"
                ) from exc
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def manifest(self) -> CapabilityManifest:
        """Fetch what the remote agent advertises. Errors surface at registration time
        (loudly) rather than being swallowed — an agent we can't reach can't be wired."""
        resp = self._http().get(f"{self.base_url}/manifest")
        resp.raise_for_status()
        manifest = CapabilityManifest.model_validate(resp.json())
        manifest.agent = self.name  # the gateway keys on our name, never the agent's
        return manifest

    def invoke(self, call: ToolCall) -> ToolResult:
        """Relay an already-authorized call to the remote agent. A transport failure
        becomes a clean failed :class:`ToolResult` rather than an exception — the call
        was authorized; the agent merely couldn't be reached."""
        try:
            resp = self._http().post(f"{self.base_url}/invoke", json=call.model_dump())
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - any transport/HTTP error -> failed result
            return ToolResult(ok=False, error=f"{self.name} transport error: {exc}")
        return ToolResult.model_validate(resp.json())
