"""M8: the HTTP adapter — govern an agent that runs as a remote HTTP service.

The adapter is a dumb conduit: it speaks the two-method contract over JSON and
carries no authorization logic. The critical property is that enforce-then-invoke
still holds across the network boundary — a denied call never produces an HTTP
request to the remote agent.

Tests drive a fake remote agent via ``httpx.MockTransport`` (no real socket).
"""

import httpx
import pytest

from praetor.adapters import HTTPAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, CapabilityManifest, ToolCall, ToolResult

REMOTE_MANIFEST = CapabilityManifest(
    agent="whatever-it-calls-itself",
    description="A remote containment agent we don't own.",
    capabilities=[Capability(name="net.isolate", description="isolate a host", targets="host:*")],
)


def _fake_agent(record: list[httpx.Request] | None = None) -> httpx.Client:
    """An httpx client wired to an in-memory agent exposing /manifest and /invoke."""

    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        if request.url.path == "/manifest":
            return httpx.Response(200, json=REMOTE_MANIFEST.model_dump())
        if request.url.path == "/invoke":
            call = ToolCall.model_validate_json(request.content)
            result = ToolResult(ok=True, output=f"remotely isolated {call.target}")
            return httpx.Response(200, json=result.model_dump())
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://agent.test")


def _adapter(record: list | None = None) -> HTTPAdapter:
    return HTTPAdapter("containment", "http://agent.test", client=_fake_agent(record))


# ── the contract over HTTP ───────────────────────────────────────────────────


def test_manifest_is_fetched_and_renamed_to_the_adapters_name():
    m = _adapter().manifest()
    # the gateway keys on *our* name, never on what the remote agent calls itself
    assert m.agent == "containment"
    assert m.capabilities[0].name == "net.isolate"


def test_invoke_relays_the_call_and_returns_the_remote_result():
    out = _adapter().invoke(ToolCall(agent="x", action="net.isolate", target="host-9"))
    assert out.ok and out.output == "remotely isolated host-9"


def test_transport_error_becomes_a_clean_failed_result_not_an_exception():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://agent.test")
    out = HTTPAdapter("containment", "http://agent.test", client=client).invoke(
        ToolCall(agent="x", action="net.isolate", target="host-9")
    )
    assert not out.ok and "transport error" in out.error


def test_http_error_status_becomes_a_failed_result():
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(500)),
        base_url="http://agent.test",
    )
    out = HTTPAdapter("x", "http://agent.test", client=client).invoke(
        ToolCall(agent="x", action="net.isolate", target="host-9")
    )
    assert not out.ok


# ── the whole point: enforcement holds across the network boundary ───────────


def test_gateway_governs_a_remote_agent_end_to_end():
    record: list[httpx.Request] = []
    gw = Gateway()
    ident = gw.register(_adapter(record))  # manifest fetched -> 1 request
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},
    )

    decision, result = gw.dispatch(ToolCall(agent=ident.id, action="net.isolate", target="host-9"))
    assert decision.allow
    assert result.ok and result.output == "remotely isolated host-9"
    assert [r.url.path for r in record] == ["/manifest", "/invoke"]


def test_denied_call_never_reaches_the_remote_agent():
    record: list[httpx.Request] = []
    gw = Gateway()
    ident = gw.register(_adapter(record))  # /manifest
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},  # scoped to host-9 only
    )

    decision, result = gw.dispatch(
        ToolCall(agent=ident.id, action="net.isolate", target="host-OTHER")
    )
    assert not decision.allow and result is None
    # the gateway blocked the call *before* any /invoke request crossed the wire
    assert [r.url.path for r in record] == ["/manifest"]


def test_revoked_warrant_cuts_off_the_remote_agent():
    record: list[httpx.Request] = []
    gw = Gateway()
    ident = gw.register(_adapter(record))
    w = gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},
    )
    call = ToolCall(agent=ident.id, action="net.isolate", target="host-9")
    assert gw.dispatch(call)[0].allow            # one /invoke
    gw.revoke(w.wid, reason="containment complete")
    decision, result = gw.dispatch(call)
    assert not decision.allow and result is None  # no further /invoke
    assert [r.url.path for r in record] == ["/manifest", "/invoke"]


def test_missing_httpx_raises_a_clear_install_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "httpx":
            raise ModuleNotFoundError("No module named 'httpx'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    a = HTTPAdapter("x", "http://agent.test")  # no client injected -> must build httpx
    with pytest.raises(RuntimeError, match="praetor\\[http\\]"):
        a.manifest()
