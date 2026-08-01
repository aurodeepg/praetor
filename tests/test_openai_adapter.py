"""M8: the OpenAI / ChatGPT adapter — govern a hosted LLM agent under a warrant.

Same critical property as every other adapter: the gateway decides *before* invoke,
so a denied call never becomes a request to the provider (no tokens spent, no work
done). Tests drive a fake provider via ``httpx.MockTransport`` — no network, no key.
"""

import httpx
import pytest

from praetor.adapters.openai import OpenAIAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, ToolCall

CAPS = [
    Capability(name="intel.lookup", description="look up threat intel", targets="ioc:*"),
    Capability(name="intel.enrich", description="enrich an indicator", targets="ioc:*"),
]


def _fake_provider(record: list[httpx.Request] | None = None) -> httpx.Client:
    """An httpx client wired to an in-memory OpenAI-compatible endpoint."""

    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "intel: benign"}}]},
            )
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _adapter(record: list | None = None, **kw) -> OpenAIAdapter:
    return OpenAIAdapter(
        "threat-intel",
        CAPS,
        model="test-model",
        api_key="sk-test",
        client=_fake_provider(record),
        **kw,
    )


# ── the contract ─────────────────────────────────────────────────────────────


def test_manifest_is_operator_declared_not_self_reported():
    m = _adapter().manifest()
    assert m.agent == "threat-intel"
    assert [c.name for c in m.capabilities] == ["intel.lookup", "intel.enrich"]


def test_invoke_turns_an_authorized_call_into_one_completion():
    record: list[httpx.Request] = []
    out = _adapter(record).invoke(ToolCall(agent="x", action="intel.lookup", target="ioc:8.8.8.8"))
    assert out.ok and out.output == "intel: benign"
    assert len(record) == 1


def test_the_prompt_carries_only_the_authorized_action():
    record: list[httpx.Request] = []
    _adapter(record).invoke(ToolCall(agent="x", action="intel.lookup", target="ioc:8.8.8.8"))
    body = record[0].read().decode()
    assert "intel.lookup" in body and "ioc:8.8.8.8" in body
    # the model is never shown capabilities the warrant didn't authorize
    assert "intel.enrich" not in body


def test_base_url_is_configurable_so_any_compatible_endpoint_works():
    record: list[httpx.Request] = []
    a = _adapter(record, base_url="http://localhost:1234/v1")
    a.invoke(ToolCall(agent="x", action="intel.lookup", target="ioc:1.1.1.1"))
    assert str(record[0].url) == "http://localhost:1234/v1/chat/completions"


def test_provider_error_becomes_a_clean_failed_result_not_an_exception():
    def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "upstream on fire"})

    a = OpenAIAdapter(
        "threat-intel", CAPS, model="test-model", api_key="sk-test",
        client=httpx.Client(transport=httpx.MockTransport(boom)),
    )
    out = a.invoke(ToolCall(agent="x", action="intel.lookup", target="ioc:8.8.8.8"))
    assert out.ok is False and "threat-intel" in out.error


def test_missing_api_key_is_a_failed_result_with_a_clear_hint(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    a = OpenAIAdapter("threat-intel", CAPS, model="test-model", client=_fake_provider())
    out = a.invoke(ToolCall(agent="x", action="intel.lookup", target="ioc:8.8.8.8"))
    assert out.ok is False and "OPENAI_API_KEY" in out.error


# ── governed end to end ──────────────────────────────────────────────────────


def _governed(record: list) -> tuple[Gateway, str]:
    gw = Gateway()
    ident = gw.register(_adapter(record))
    return gw, ident.id


def _warrant(gw, agent_id):
    return gw.issue_warrant(
        subject=agent_id, on_behalf_of="ops@corp",
        capability="intel.lookup", scope={"target": "ioc:*"},
    )


def test_gateway_governs_a_hosted_llm_agent_end_to_end():
    record: list[httpx.Request] = []
    gw, agent_id = _governed(record)
    _warrant(gw, agent_id)
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="intel.lookup", target="ioc:8.8.8.8")
    )
    assert decision.allow and result.ok and result.output == "intel: benign"


def test_denied_call_never_reaches_the_provider():
    """The money property: an unauthorized call costs zero tokens."""
    record: list[httpx.Request] = []
    gw, agent_id = _governed(record)
    _warrant(gw, agent_id)
    # out of scope for the issued warrant
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="intel.enrich", target="ioc:8.8.8.8")
    )
    assert not decision.allow and result is None
    assert record == []  # no request ever left the gateway


def test_revoked_warrant_cuts_the_llm_agent_off():
    record: list[httpx.Request] = []
    gw, agent_id = _governed(record)
    w = _warrant(gw, agent_id)
    gw.dispatch(ToolCall(agent=agent_id, action="intel.lookup", target="ioc:8.8.8.8"))
    assert len(record) == 1
    gw.revoke(w.wid)
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="intel.lookup", target="ioc:8.8.8.8")
    )
    assert not decision.allow and result is None
    assert len(record) == 1  # still one — the revoked agent made no further call


def test_missing_httpx_raises_a_clear_install_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_httpx(name, *args, **kw):
        if name == "httpx":
            raise ModuleNotFoundError("No module named 'httpx'")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", no_httpx)
    a = OpenAIAdapter("threat-intel", CAPS, model="test-model", api_key="sk-test")
    with pytest.raises(RuntimeError, match=r"praetor\[llm\]"):
        a._http()
