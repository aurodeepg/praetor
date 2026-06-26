"""The Policy Enforcement Point.

Every call flows through here. Given a tool call, the PEP looks only at the live
ledger — never at a token in isolation — and returns an allow/deny decision bound to
the warrant that authorized it. Because all traffic passes through this one point,
revocation is just "deny the next call."

The logic is pure and deterministic by design: identity, scoping, and enforcement are
crypto + policy, not inference. Intelligence layers on top (the matcher, the Phase-2
orchestrator), never here.
"""

from __future__ import annotations

from praetor.models import Decision, ToolCall
from praetor.warrants.ledger import WarrantLedger
from praetor.warrants.scope import warrant_authorizes


def decide(ledger: WarrantLedger, call: ToolCall, now: float) -> Decision:
    """Resolve a single call against the live ledger."""
    held = ledger.for_subject(call.agent, now)

    if not held:
        return Decision(
            allow=False,
            reason="no valid warrant (revoked or expired) — denied at the gateway",
            call=call,
        )

    # Allow on the first warrant that authorizes the call.
    best_denial = "no held warrant covers this action"
    for w in held:
        ok, reason = warrant_authorizes(w, call)
        if ok:
            return Decision(allow=True, reason=reason, warrant_id=w.wid, call=call)
        best_denial = reason  # keep the most specific reason for the audit trail

    return Decision(allow=False, reason=best_denial, call=call)
