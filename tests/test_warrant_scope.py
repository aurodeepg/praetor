"""M1: the warrant model and pure scope matching — the atomic unit of authority."""

from praetor.models import ToolCall, Warrant
from praetor.warrants import (
    action_matches,
    excluded,
    target_in_scope,
    warrant_authorizes,
)


def _w(**kw):
    base = dict(
        subject="agent:containment",
        on_behalf_of="incident://ir-4821",
        capability="net.isolate",
        issued_at=0,
        expires_at=10,
    )
    base.update(kw)
    return Warrant(**base)


# --- action matching: exact, glob, and namespace-prefix ---------------------


def test_action_matches_exact_glob_and_prefix():
    assert action_matches("net.isolate", "net.isolate")                     # exact
    assert action_matches("net.quarantine.isolate-host", "net.quarantine")  # dotted prefix
    assert action_matches("logs.read", "logs.*")                            # glob
    assert action_matches("intel:lookup", "intel:lookup")                   # colon namespace
    assert action_matches("intel:lookup.bulk", "intel")                     # colon prefix
    assert not action_matches("fs.write", "net.isolate")
    assert not action_matches("network.isolate", "net")                     # not a prefix boundary


def test_glob_matching_is_case_sensitive_on_every_platform():
    # Guards against fnmatch's os.path.normcase folding (Windows): an authz decision
    # must be deterministic regardless of the host OS.
    assert action_matches("logs.read", "logs.*")
    assert not action_matches("LOGS.read", "logs.*")
    assert not target_in_scope("HOST-9", {"target": "host-*"})


def test_excludes_block_even_when_capability_matches():
    assert excluded("fs.write", ["fs.write", "remediate"])
    assert excluded("net.quarantine.isolate-host", ["net.quarantine"])      # prefix exclude
    assert not excluded("read:logs", ["write"])
    assert not excluded("anything", [])


# --- target scope -----------------------------------------------------------


def test_target_scope():
    assert target_in_scope("db-prod-12", {"target": "db-prod-12"})          # exact
    assert target_in_scope("host-9", {"target": "host-*"})                  # glob
    assert target_in_scope("anything", {})                                  # unconstrained
    assert target_in_scope(None, {})                                        # unconstrained
    assert not target_in_scope("other", {"target": "db-prod-12"})
    assert not target_in_scope(None, {"target": "db-prod-12"})              # needs a target


# --- end-to-end authorization with reasons ----------------------------------


def test_warrant_authorizes_the_scoped_call():
    w = _w(scope={"target": "db-prod-12"}, excludes=["fs.write"])
    ok, reason = warrant_authorizes(
        w, ToolCall(agent="agent:containment", action="net.isolate", target="db-prod-12")
    )
    assert ok
    assert "match" in reason


def test_denies_action_outside_capability():
    w = _w(scope={"target": "db-prod-12"})
    ok, reason = warrant_authorizes(
        w, ToolCall(agent="agent:containment", action="fs.write", target="db-prod-12")
    )
    assert not ok and "∉" in reason


def test_denies_target_outside_scope():
    w = _w(scope={"target": "db-prod-12"})
    ok, reason = warrant_authorizes(
        w, ToolCall(agent="agent:containment", action="net.isolate", target="db-prod-99")
    )
    assert not ok and "scope" in reason


def test_excluded_escalation_is_blocked():
    # Capability would otherwise cover the action, but it's explicitly excluded.
    w = _w(capability="net", excludes=["net.isolate"])
    ok, reason = warrant_authorizes(
        w, ToolCall(agent="agent:containment", action="net.isolate", target="x")
    )
    assert not ok and "exclude-list" in reason


# --- the warrant's time-boxing helpers (validity, kept separate from scope) --


def test_is_active_window_and_revocation():
    w = _w(issued_at=100, expires_at=200)
    assert not w.is_active(99)        # before issuance
    assert w.is_active(100)           # at issuance (inclusive)
    assert w.is_active(199)
    assert not w.is_active(200)       # at expiry (exclusive)
    w.revoked = True
    assert not w.is_active(150)       # revoked overrides the window


def test_remaining_and_ttl():
    w = _w(issued_at=100, expires_at=160)
    assert w.ttl == 60
    assert w.remaining(130) == 30
    assert w.remaining(200) == 0      # never negative
    w.revoked = True
    assert w.remaining(130) == 0      # revoked has no authority left


def test_warrant_gets_an_id_and_defaults():
    w = _w()
    assert w.wid.startswith("w:")
    assert w.trust == "unverified"
    assert w.excludes == [] and w.scope == {}
    assert not w.revoked
