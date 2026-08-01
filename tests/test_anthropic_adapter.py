"""M8: the Anthropic / Claude adapter — the third provider shape, same governance.

The Messages API is the one genuinely non-OpenAI-compatible surface (x-api-key +
anthropic-version headers, top-level system, required max_tokens, content-block list,
refusal stop_reason). What must not vary is the warrant check: enforce-before-invoke
still holds, so a denied call never becomes a request to Anthropic.
"""

import httpx

from praetor.adapters.anthropic import ANTHROPIC_VERSION, AnthropicAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, ToolCall

CAPS = [
    Capability(name="postmortem.write", description="draft a postmortem", targets="inc:*"),
    Capability(name="postmortem.publish", description="publish it", targets="inc:*"),
]

OK = {
    "content": [{"type": "text", "text": "postmortem drafted"}],
    "stop_reason": "end_turn",
}


def _fake_anthropic(record: list[httpx.Request] | None = None, payload: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json=payload if payload is not None else OK)
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _adapter(record: list | None = None, payload: dict | None = None, **kw) -> AnthropicAdapter:
    return AnthropicAdapter(
        "scribe", CAPS, model="test-model", api_key="sk-ant-test",
        client=_fake_anthropic(record, payload), **kw,
    )


# ── the provider-specific translation ────────────────────────────────────────


def test_invoke_speaks_the_messages_api_shape():
    record: list[httpx.Request] = []
    out = _adapter(record).invoke(ToolCall(agent="x", action="postmortem.write", target="inc:42"))
    assert out.ok and out.output == "postmortem drafted"

    req = record[0]
    assert req.url.path.endswith("/messages")
    assert req.headers["x-api-key"] == "sk-ant-test"
    assert req.headers["anthropic-version"] == ANTHROPIC_VERSION


def test_request_body_matches_the_messages_contract():
    import json

    record: list[httpx.Request] = []
    _adapter(record).invoke(ToolCall(agent="x", action="postmortem.write", target="inc:42"))
    body = json.loads(record[0].read())

    assert isinstance(body["system"], str)          # top-level, not a message role
    assert body["messages"] == [{"role": "user", "content": body["messages"][0]["content"]}]
    assert body["max_tokens"] > 0                   # required by the API
    # current Claude models reject sampling params with a 400 — we must not send them
    assert "temperature" not in body and "top_p" not in body and "top_k" not in body
    assert "postmortem.write" in body["messages"][0]["content"]
    assert "postmortem.publish" not in body["messages"][0]["content"]


def test_only_text_blocks_are_joined():
    payload = {
        "content": [
            {"type": "thinking", "thinking": ""},
            {"type": "text", "text": "part one "},
            {"type": "text", "text": "part two"},
        ],
        "stop_reason": "end_turn",
    }
    out = _adapter(payload=payload).invoke(ToolCall(agent="x", action="postmortem.write"))
    assert out.output == "part one part two"


def test_a_refusal_is_a_failed_result_not_an_empty_success():
    payload = {"content": [], "stop_reason": "refusal"}
    out = _adapter(payload=payload).invoke(ToolCall(agent="x", action="postmortem.write"))
    assert out.ok is False and "refusal" in out.error


def test_empty_content_is_a_failed_result():
    payload = {"content": [], "stop_reason": "max_tokens"}
    out = _adapter(payload=payload).invoke(ToolCall(agent="x", action="postmortem.write"))
    assert out.ok is False and "max_tokens" in out.error


def test_missing_api_key_is_a_failed_result_with_a_clear_hint(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = AnthropicAdapter("scribe", CAPS, model="test-model", client=_fake_anthropic())
    out = a.invoke(ToolCall(agent="x", action="postmortem.write"))
    assert out.ok is False and "ANTHROPIC_API_KEY" in out.error


# ── governance is identical across providers ─────────────────────────────────


def test_denied_call_never_reaches_anthropic():
    record: list[httpx.Request] = []
    gw = Gateway()
    agent_id = gw.register(_adapter(record)).id
    gw.issue_warrant(
        subject=agent_id, on_behalf_of="ops@corp",
        capability="postmortem.write", scope={"target": "inc:*"},
    )
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="postmortem.write", target="inc:42")
    )
    assert decision.allow and result.output == "postmortem drafted"

    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="postmortem.publish", target="inc:42")
    )
    assert not decision.allow and result is None
    assert len(record) == 1  # only the authorized call ever hit the provider
