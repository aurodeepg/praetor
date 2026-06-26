"""M5: the adapter contract + mock adapter + gateway dispatch.

Dispatch is enforce-then-invoke: a denied call must never reach the adapter. The
gateway is the policy enforcement point that sits between intent and action.
"""

from praetor.adapters import AgentAdapter, MockAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, ToolCall, ToolResult

ISOLATE = Capability(name="net.isolate", description="isolate a host", targets="host:*")


def _containment(record: list | None = None) -> MockAdapter:
    """A containment agent; if `record` is given, every invoke appends its action to
    it — so a test can assert the adapter was (or was *not*) called."""
    handlers = None
    if record is not None:
        def _h(call: ToolCall) -> ToolResult:
            record.append(call.action)
            return ToolResult(ok=True, output=f"isolated {call.target}")
        handlers = {"net.isolate": _h}
    return MockAdapter("containment", [ISOLATE], trust="internal", handlers=handlers)


def _grant_isolate(gw: Gateway, **kw) -> None:
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"}, **kw,
    )


# ── the contract / mock adapter ──────────────────────────────────────────────


def test_mock_adapter_satisfies_the_contract_and_advertises_a_manifest():
    a = _containment()
    assert isinstance(a, AgentAdapter)
    m = a.manifest()
    assert m.agent == "containment" and m.capabilities == [ISOLATE]


def test_mock_adapter_invoke_uses_handlers_then_falls_back_to_canned_output():
    a = MockAdapter("forensics", [Capability(name="logs.read")])
    out = a.invoke(ToolCall(agent="x", action="logs.read", target="app"))
    assert out.ok and "forensics executed logs.read(app)" == out.output


# ── gateway.register(adapter) ────────────────────────────────────────────────


def test_register_adapter_issues_identity_registers_manifest_and_wires_adapter():
    gw = Gateway()
    ident = gw.register(_containment())
    assert ident.trust == "internal"
    assert "containment" in gw.registry.agents()
    assert gw._adapters[ident.id].name == "containment"


# ── dispatch: enforce then invoke ────────────────────────────────────────────


def test_dispatch_runs_the_adapter_only_for_an_authorized_call():
    gw = Gateway()
    calls: list[str] = []
    ident = gw.register(_containment(calls))
    _grant_isolate(gw)

    decision, result = gw.dispatch(ToolCall(agent=ident.id, action="net.isolate", target="host-9"))
    assert decision.allow
    assert result.ok and result.output == "isolated host-9"
    assert calls == ["net.isolate"]  # adapter actually ran, once


def test_dispatch_denies_out_of_scope_and_never_calls_the_adapter():
    gw = Gateway()
    calls: list[str] = []
    ident = gw.register(_containment(calls))
    _grant_isolate(gw)  # scoped to host-9

    decision, result = gw.dispatch(
        ToolCall(agent=ident.id, action="net.isolate", target="host-OTHER")
    )
    assert not decision.allow and result is None
    assert calls == []  # the adapter was never reached


def test_dispatch_after_revoke_is_denied_and_does_not_invoke():
    gw = Gateway()
    calls: list[str] = []
    ident = gw.register(_containment(calls))
    w = gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir-1",
        capability="net.isolate", scope={"target": "host-9"},
    )
    # allowed before revocation
    assert gw.dispatch(ToolCall(agent=ident.id, action="net.isolate", target="host-9"))[0].allow
    gw.revoke(w.wid, reason="containment complete")
    decision, result = gw.dispatch(ToolCall(agent=ident.id, action="net.isolate", target="host-9"))
    assert not decision.allow and result is None
    assert calls == ["net.isolate"]  # only the pre-revocation call ran


def test_dispatch_for_authorized_agent_without_an_adapter_reports_cleanly():
    gw = Gateway()
    gw.register_agent("containment", trust="internal")  # identity only, no adapter
    ident = gw._identities["containment"]
    _grant_isolate(gw)
    decision, result = gw.dispatch(ToolCall(agent=ident.id, action="net.isolate", target="host-9"))
    assert decision.allow
    assert result is not None and not result.ok and "no adapter" in result.error
