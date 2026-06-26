"""M3: the authority core — issue · enforce · revoke + audit, end to end.

Uses a logical clock so time-dependent behaviour (TTL expiry) is deterministic.
"""

import jwt
import pytest

from praetor.gateway import Gateway
from praetor.models import ToolCall


class Clock:
    """A hand-cranked clock so tests advance time explicitly."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, dt: float) -> None:
        self.t += dt


@pytest.fixture
def gw():
    clock = Clock()
    g = Gateway(clock=clock)
    g.clock = clock  # expose for tests to advance
    return g


def _call(agent, action, target=None):
    return ToolCall(agent=agent, action=action, target=target)


# ── issue ───────────────────────────────────────────────────────────────────


def test_issue_binds_subject_signs_token_and_lands_in_ledger(gw):
    ident = gw.register_agent("containment", trust="internal")
    w = gw.issue_warrant(
        subject="containment",  # resolved by name → identity id
        on_behalf_of="incident://ir-4821",
        capability="net.isolate",
        scope={"target": "host-9"},
        ttl=600,
        reason="contain lateral movement",
    )
    assert w.subject == ident.id
    assert gw.ledger.get(w.wid) is w
    assert w in gw.active_warrants()

    # Token is signed by the gateway and carries the warrant's claims + an exp.
    claims = gw.identity.verify(w.token)
    assert claims["sub"] == ident.id
    assert claims["cap"] == "net.isolate"
    assert claims["wid"] == w.wid
    assert claims["exp"] == int(w.expires_at)


# ── enforce: allow / deny ────────────────────────────────────────────────────


def test_enforce_allows_the_scoped_call_and_denies_out_of_scope(gw):
    ident = gw.register_agent("containment")
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir",
        capability="net.isolate", scope={"target": "host-9"}, excludes=["fs.write"],
    )

    ok = gw.enforce(_call(ident.id, "net.isolate", "host-9"))
    assert ok.allow and ok.warrant_id

    wrong_target = gw.enforce(_call(ident.id, "net.isolate", "host-other"))
    assert not wrong_target.allow and "scope" in wrong_target.reason

    wrong_action = gw.enforce(_call(ident.id, "fs.write", "host-9"))
    assert not wrong_action.allow


def test_enforce_denies_an_agent_with_no_warrant(gw):
    ident = gw.register_agent("intruder")
    d = gw.enforce(_call(ident.id, "net.isolate", "host-9"))
    assert not d.allow and "no valid warrant" in d.reason


def test_excluded_escalation_is_blocked_even_under_a_broad_capability(gw):
    ident = gw.register_agent("forensics")
    gw.issue_warrant(
        subject="forensics", on_behalf_of="incident://ir",
        capability="logs", excludes=["logs.delete"],  # read-ish grant, no destruction
    )
    assert gw.enforce(_call(ident.id, "logs.read")).allow
    blocked = gw.enforce(_call(ident.id, "logs.delete"))
    assert not blocked.allow and "exclude-list" in blocked.reason


# ── revoke: the next call is denied ──────────────────────────────────────────


def test_revoke_cuts_the_agent_off_on_the_very_next_call(gw):
    ident = gw.register_agent("threat-intel", trust="3rd-party")
    w = gw.issue_warrant(
        subject="threat-intel", on_behalf_of="incident://ir", capability="intel.lookup",
    )
    assert gw.enforce(_call(ident.id, "intel.lookup")).allow      # before

    revoked = gw.revoke(w.wid, reason="phase change — intel no longer needed")
    assert revoked and revoked.revoked and revoked.revoke_cause == "manual"

    after = gw.enforce(_call(ident.id, "intel.lookup"))           # after
    assert not after.allow
    assert w not in gw.active_warrants()


def test_revoking_unknown_or_twice_is_a_noop(gw):
    assert gw.revoke("w:does-not-exist") is None
    gw.register_agent("a")
    w = gw.issue_warrant(subject="a", on_behalf_of="t", capability="x")
    assert gw.revoke(w.wid) is not None
    assert gw.revoke(w.wid) is None  # already revoked


# ── TTL auto-expiry ──────────────────────────────────────────────────────────


def test_ttl_elapsed_warrant_auto_expires_at_enforce(gw):
    ident = gw.register_agent("containment")
    gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir",
        capability="net.isolate", scope={"target": "host-9"}, ttl=60,
    )
    assert gw.enforce(_call(ident.id, "net.isolate", "host-9")).allow

    gw.clock.tick(61)  # past expiry
    expired = gw.enforce(_call(ident.id, "net.isolate", "host-9"))
    assert not expired.allow
    # and it was recorded as a ttl revocation in the trail
    assert any(e.kind == "revoke" and e.cause == "ttl" for e in gw.audit.entries())


# ── audit trail ──────────────────────────────────────────────────────────────


def test_audit_trail_binds_every_event_to_identity_and_warrant(gw):
    ident = gw.register_agent("containment")
    w = gw.issue_warrant(
        subject="containment", on_behalf_of="incident://ir",
        capability="net.isolate", scope={"target": "host-9"},
    )
    gw.enforce(_call(ident.id, "net.isolate", "host-9"))   # ALLOW
    gw.enforce(_call(ident.id, "fs.write", "host-9"))      # DENY
    gw.revoke(w.wid)

    kinds = [e.kind for e in gw.audit.entries()]
    assert kinds.count("issue") == 1
    assert kinds.count("decision") == 2
    assert kinds.count("revoke") == 1

    trail = gw.audit.for_warrant(w.wid)
    assert {e.kind for e in trail} >= {"issue", "revoke"}
    decisions = [e for e in gw.audit.entries() if e.kind == "decision"]
    assert {e.decision for e in decisions} == {"ALLOW", "DENY"}


def test_snapshot_redacts_the_token(gw):
    gw.register_agent("containment")
    gw.issue_warrant(subject="containment", on_behalf_of="t", capability="net.isolate")
    snap = gw.snapshot()
    assert snap["warrants"] and "token" not in snap["warrants"][0]
    assert snap["warrants"][0]["remaining"] > 0


# ── defense in depth: the token carries a real exp claim ─────────────────────


def test_issued_token_carries_exp_equal_to_warrant_expiry(gw):
    gw.register_agent("containment")
    w = gw.issue_warrant(
        subject="containment", on_behalf_of="t", capability="net.isolate", ttl=600,
    )
    # The gateway's own verify ignores exp (the ledger owns liveness)...
    claims = gw.identity.verify(w.token)
    assert claims["wid"] == w.wid
    # ...but the exp claim is present and correct, so an out-of-band verifier that
    # *does* check exp can reject a stale token — defense in depth.
    assert claims["exp"] == int(w.expires_at) == int(gw.now() + 600)
    decoded = jwt.decode(
        w.token, gw.identity.public_pem(), algorithms=["RS256"],
        issuer="praetor", options={"verify_exp": False},
    )
    assert decoded["exp"] == int(w.expires_at)
