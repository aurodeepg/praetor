"""Microsoft Copilot Studio adapter — govern a Copilot Studio agent under a warrant.

Copilot Studio agents are reached over the **Direct Line 3.0** REST API (the same
Azure Bot Service / Bot Framework channel used by custom apps). That makes this the
one adapter in the family whose shape isn't request/response at all — it's a
*conversation*:

    POST {base_url}/conversations                      -> start, returns conversationId
    POST {base_url}/conversations/{id}/activities      -> send one activity (a message)
    GET  {base_url}/conversations/{id}/activities?watermark=N -> poll for replies

So :meth:`_complete` starts a conversation once, posts the authorized action as an
activity, then polls for the agent's reply, using the watermark to read only what's
new and filtering out the echo of its own message. The conversation is reused across
calls, so a governed agent keeps its context.

**Two honest limitations, both by design:**

* Direct Line has no system-prompt channel — an agent's persona and instructions live
  in Copilot Studio, not in the request. The adapter therefore sends only the task
  text; the ``system`` prompt is not transmitted. This costs nothing in governance:
  the gateway decides ALLOW *before* ``invoke``, so what the agent may do is set by
  the warrant, not by anything we could put in a prompt.
* Replies are polled, not streamed. ``poll_interval``/``max_polls`` bound the wait,
  and a silent agent becomes a clean failed result rather than a hang.

Auth is a Direct Line **secret** (or a pre-minted token) as a bearer credential.
Requires the ``llm`` extra (``httpx``) and ``COPILOT_STUDIO_DIRECTLINE_SECRET``.
"""

from __future__ import annotations

import os
import time
from typing import Any

from praetor.adapters.llm import LLMAgentAdapter
from praetor.models import Capability

DEFAULT_BASE_URL = "https://directline.botframework.com/v3/directline"
#: Identifies our side of the conversation, so we can tell replies from our own echo.
USER_ID = "praetor-gateway"


class CopilotStudioAdapter(LLMAgentAdapter):
    """A Microsoft Copilot Studio agent as a governed Praetor agent.

    Unlike the completion-style provider adapters this one has no ``model`` — the
    model is chosen inside Copilot Studio. What identifies the agent here is the
    Direct Line credential.
    """

    def __init__(
        self,
        name: str,
        capabilities: list[Capability],
        *,
        secret: str | None = None,
        base_url: str | None = None,
        trust: str = "3rd-party · copilot-studio · unverified",
        description: str = "",
        timeout: float = 60.0,
        poll_interval: float = 1.0,
        max_polls: int = 30,
        client: Any | None = None,
    ) -> None:
        super().__init__(
            name,
            capabilities,
            model="copilot-studio",  # the model lives in Copilot Studio, not here
            trust=trust,
            description=description,
            timeout=timeout,
            client=client,
        )
        self.base_url = (
            base_url or os.environ.get("COPILOT_STUDIO_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self._secret = self._key(
            secret, "COPILOT_STUDIO_DIRECTLINE_SECRET", "DIRECTLINE_SECRET"
        )
        self._poll_interval = poll_interval
        self._max_polls = max_polls
        self._conversation_id: str | None = None
        self._watermark: str | None = None
        self.backend = "copilot-studio:directline"

    # ── Direct Line plumbing ─────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._secret}", "content-type": "application/json"}

    def _conversation(self) -> str:
        """Start a conversation on first use and reuse it thereafter, so the governed
        agent keeps its context across calls."""
        if self._conversation_id is None:
            resp = self._http().post(f"{self.base_url}/conversations", headers=self._headers())
            resp.raise_for_status()
            cid = resp.json().get("conversationId")
            if not cid:
                raise RuntimeError("Direct Line did not return a conversationId")
            self._conversation_id = cid
        return self._conversation_id

    def _complete(self, system: str, prompt: str) -> str:
        # `system` is intentionally unused — see the module docstring: Direct Line has
        # no system-prompt channel, and the agent's persona is configured in Copilot
        # Studio. Authority still comes from the warrant, not from the prompt.
        if not self._secret:
            raise RuntimeError(
                "no Direct Line secret — set COPILOT_STUDIO_DIRECTLINE_SECRET or pass secret="
            )
        cid = self._conversation()
        resp = self._http().post(
            f"{self.base_url}/conversations/{cid}/activities",
            headers=self._headers(),
            json={"type": "message", "from": {"id": USER_ID}, "text": prompt},
        )
        resp.raise_for_status()
        return self._await_reply(cid)

    def _await_reply(self, cid: str) -> str:
        """Poll the activity feed until the agent answers, or give up cleanly."""
        for attempt in range(self._max_polls):
            if attempt:
                time.sleep(self._poll_interval)
            url = f"{self.base_url}/conversations/{cid}/activities"
            params = {"watermark": self._watermark} if self._watermark else None
            resp = self._http().get(url, headers=self._headers(), params=params)
            resp.raise_for_status()
            payload = resp.json()
            self._watermark = payload.get("watermark") or self._watermark
            text = self._agent_text(payload.get("activities") or [])
            if text:
                return text
        raise RuntimeError(f"no reply from the agent after {self._max_polls} polls")

    @staticmethod
    def _agent_text(activities: list[dict]) -> str:
        """Join the text of the agent's message activities, skipping our own echo."""
        return "\n".join(
            a["text"]
            for a in activities
            if a.get("type") == "message"
            and (a.get("from") or {}).get("id") != USER_ID
            and a.get("text")
        )
