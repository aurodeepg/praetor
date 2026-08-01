"""M8: the Copilot Studio adapter — a conversation-shaped agent, governed identically.

Direct Line is not request/response: start a conversation, post an activity, poll the
feed with a watermark. This is the strongest test of the adapter contract — if a
conversational agent still looks like `manifest()` + `invoke()` to the gateway, the
abstraction holds. Fake Direct Line service via ``httpx.MockTransport``.
"""

import httpx

from praetor.adapters.copilot_studio import USER_ID, CopilotStudioAdapter
from praetor.gateway import Gateway
from praetor.models import Capability, ToolCall

CAPS = [
    Capability(name="ticket.create", description="open a ticket", targets="inc:*"),
    Capability(name="ticket.close", description="close a ticket", targets="inc:*"),
]


class FakeDirectLine:
    """An in-memory Direct Line service: conversations, activities, watermark."""

    def __init__(self, reply: str | None = "ticket INC-42 created", silent: bool = False):
        self.reply = reply
        self.silent = silent
        self.requests: list[httpx.Request] = []
        self.posted: list[dict] = []
        self.conversations = 0
        self._pending: list[dict] = []
        self._n = 0

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        import json

        self.requests.append(request)
        path = request.url.path

        if request.method == "POST" and path.endswith("/conversations"):
            self.conversations += 1
            return httpx.Response(200, json={"conversationId": "conv-1"})

        if request.method == "POST" and path.endswith("/activities"):
            body = json.loads(request.read())
            self.posted.append(body)
            # echo our own message back, as the real service does
            self._pending.append({"type": "message", "from": {"id": USER_ID}, "text": body["text"]})
            if not self.silent:
                self._pending.append(
                    {"type": "typing", "from": {"id": "agent"}},  # non-message noise
                )
                self._pending.append(
                    {"type": "message", "from": {"id": "agent"}, "text": self.reply}
                )
            return httpx.Response(200, json={"id": "act-1"})

        if request.method == "GET" and path.endswith("/activities"):
            batch, self._pending = self._pending, []
            self._n += 1
            return httpx.Response(200, json={"activities": batch, "watermark": str(self._n)})

        return httpx.Response(404)


def _adapter(svc: FakeDirectLine, **kw) -> CopilotStudioAdapter:
    return CopilotStudioAdapter(
        "ticketer", CAPS, secret="dl-secret", client=svc.client(),
        poll_interval=0, **kw,
    )


# ── the conversational translation ───────────────────────────────────────────


def test_invoke_starts_a_conversation_posts_an_activity_and_reads_the_reply():
    svc = FakeDirectLine()
    out = _adapter(svc).invoke(ToolCall(agent="x", action="ticket.create", target="inc:42"))
    assert out.ok and out.output == "ticket INC-42 created"
    assert svc.conversations == 1
    assert svc.posted[0]["type"] == "message" and svc.posted[0]["from"]["id"] == USER_ID
    assert "ticket.create" in svc.posted[0]["text"] and "inc:42" in svc.posted[0]["text"]
    assert all(r.headers["Authorization"] == "Bearer dl-secret" for r in svc.requests)


def test_the_conversation_is_reused_across_calls():
    """A governed agent keeps its context — we don't restart the conversation."""
    svc = FakeDirectLine()
    a = _adapter(svc)
    a.invoke(ToolCall(agent="x", action="ticket.create", target="inc:42"))
    a.invoke(ToolCall(agent="x", action="ticket.create", target="inc:43"))
    assert svc.conversations == 1
    assert len(svc.posted) == 2


def test_our_own_echoed_message_is_not_mistaken_for_the_reply():
    svc = FakeDirectLine(reply="the real answer")
    out = _adapter(svc).invoke(ToolCall(agent="x", action="ticket.create", target="inc:42"))
    assert out.output == "the real answer"  # not the echo of what we sent


def test_the_watermark_advances_so_replies_are_not_re_read():
    svc = FakeDirectLine()
    a = _adapter(svc)
    a.invoke(ToolCall(agent="x", action="ticket.create", target="inc:42"))
    first = a._watermark
    a.invoke(ToolCall(agent="x", action="ticket.create", target="inc:43"))
    assert first is not None and a._watermark != first
    polls = [r for r in svc.requests if r.method == "GET"]
    assert "watermark=" in str(polls[-1].url)


def test_a_silent_agent_becomes_a_failed_result_not_a_hang():
    svc = FakeDirectLine(silent=True)
    out = _adapter(svc, max_polls=3).invoke(ToolCall(agent="x", action="ticket.create"))
    assert out.ok is False and "no reply" in out.error


def test_missing_secret_is_a_failed_result_with_a_clear_hint(monkeypatch):
    monkeypatch.delenv("COPILOT_STUDIO_DIRECTLINE_SECRET", raising=False)
    monkeypatch.delenv("DIRECTLINE_SECRET", raising=False)
    svc = FakeDirectLine()
    a = CopilotStudioAdapter("ticketer", CAPS, client=svc.client(), poll_interval=0)
    out = a.invoke(ToolCall(agent="x", action="ticket.create"))
    assert out.ok is False and "COPILOT_STUDIO_DIRECTLINE_SECRET" in out.error
    assert svc.conversations == 0  # never even opened a conversation


# ── governance is identical across every provider shape ──────────────────────


def test_denied_call_never_reaches_copilot_studio():
    svc = FakeDirectLine()
    gw = Gateway()
    agent_id = gw.register(_adapter(svc)).id
    gw.issue_warrant(
        subject=agent_id, on_behalf_of="ops@corp",
        capability="ticket.create", scope={"target": "inc:*"},
    )
    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="ticket.create", target="inc:42")
    )
    assert decision.allow and result.ok

    decision, result = gw.dispatch(
        ToolCall(agent=agent_id, action="ticket.close", target="inc:42")
    )
    assert not decision.allow and result is None
    assert len(svc.posted) == 1  # the denied call never became an activity
