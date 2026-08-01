"""M8: the Gemini adapter — the same governance over a different provider shape.

Gemini's native API differs from Chat Completions (systemInstruction, contents/parts,
x-goog-api-key), which is exactly why it gets its own adapter. What must *not* differ
is the governance: enforce-before-invoke still holds, so a denied call never becomes a
request to Google. Fake provider via ``httpx.MockTransport`` — no network, no key.
"""

import httpx

from praetor.adapters.gemini import GeminiAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, ToolCall

CAPS = [
    Capability(name="report.draft", description="draft an incident report", targets="inc:*"),
    Capability(name="report.publish", description="publish a report", targets="inc:*"),
]


def _fake_gemini(record: list[httpx.Request] | None = None, payload: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        if request.url.path.endswith(":generateContent"):
            return httpx.Response(200, json=payload or {
                "candidates": [{"content": {"parts": [{"text": "draft ready"}]}}]
            })
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _adapter(record: list | None = None, payload: dict | None = None, **kw) -> GeminiAdapter:
    return GeminiAdapter(
        "drafter", CAPS, model="test-model", api_key="k",
        client=_fake_gemini(record, payload), **kw,
    )


# ── the provider-specific translation ────────────────────────────────────────


def test_invoke_speaks_the_native_generate_content_shape():
    record: list[httpx.Request] = []
    out = _adapter(record).invoke(ToolCall(agent="x", action="report.draft", target="inc:42"))
    assert out.ok and out.output == "draft ready"
    req = record[0]
    assert req.url.path.endswith("/models/test-model:generateContent")
    assert req.headers["x-goog-api-key"] == "k"
    body = req.read().decode()
    assert "systemInstruction" in body and "report.draft" in body and "inc:42" in body


def test_multi_part_answers_are_joined():
    payload = {"candidates": [{"content": {"parts": [{"text": "a"}, {"text": "b"}]}}]}
    out = _adapter(payload=payload).invoke(ToolCall(agent="x", action="report.draft"))
    assert out.output == "ab"


def test_a_blocked_response_is_a_failed_result_not_an_empty_success():
    payload = {"candidates": [], "promptFeedback": {"blockReason": "SAFETY"}}
    out = _adapter(payload=payload).invoke(ToolCall(agent="x", action="report.draft"))
    assert out.ok is False and "SAFETY" in out.error


def test_base_url_is_configurable():
    record: list[httpx.Request] = []
    a = _adapter(record, base_url="http://localhost:9/v1beta")
    a.invoke(ToolCall(agent="x", action="report.draft"))
    assert str(record[0].url).startswith("http://localhost:9/v1beta/models/")


def test_missing_api_key_is_a_failed_result_with_a_clear_hint(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    a = GeminiAdapter("drafter", CAPS, model="test-model", client=_fake_gemini())
    out = a.invoke(ToolCall(agent="x", action="report.draft"))
    assert out.ok is False and "GEMINI_API_KEY" in out.error


# ── governance is identical across providers ─────────────────────────────────


def test_denied_call_never_reaches_gemini():
    record: list[httpx.Request] = []
    gw = Gateway()
    agent_id = gw.register(_adapter(record)).id
    gw.issue_warrant(
        subject=agent_id, on_behalf_of="ops@corp",
        capability="report.draft", scope={"target": "inc:*"},
    )
    ok_decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="report.draft", target="inc:42")
    )
    assert ok_decision.allow and result.output == "draft ready"

    # publish was advertised in the manifest but never warranted
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="report.publish", target="inc:42")
    )
    assert not decision.allow and result is None
    assert len(record) == 1  # only the authorized call ever hit the provider
