"""M4: capability registry + the deterministic ($0) matcher — the cheap AI seed.

The matcher only *proposes*: it ranks registered capabilities against a free-form
requirement and suggests a least-privilege scope. Issuing authority stays an explicit
gateway action.
"""

from praetor.gateway import Gateway
from praetor.matcher import DeterministicMatcher, MatchResult
from praetor.models import Capability, CapabilityManifest, ToolCall
from praetor.registry import CapabilityRegistry

# A small incident-response roster used across the matcher tests.
ROSTER = {
    "containment": [
        Capability(name="net.isolate", description="isolate a host from the network",
                   targets="host:*"),
    ],
    "forensics": [
        Capability(name="logs.read", description="read and inspect host and app logs",
                   targets="logs:*"),
    ],
    "threat-intel": [
        Capability(name="intel.lookup", description="enrich an indicator via threat intel"),
    ],
}


def _registry() -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for agent, caps in ROSTER.items():
        reg.register(CapabilityManifest(agent=agent, capabilities=caps))
    return reg


# ── registry ─────────────────────────────────────────────────────────────────


def test_registry_tracks_manifests_and_flattens_capabilities():
    reg = _registry()
    assert set(reg.agents()) == {"containment", "forensics", "threat-intel"}
    pairs = reg.capabilities()
    assert len(pairs) == 3
    assert ("containment", ROSTER["containment"][0]) in pairs


def test_registry_register_is_idempotent_per_agent():
    reg = _registry()
    reg.register(CapabilityManifest(agent="forensics", capabilities=[]))  # replace
    assert reg.manifest("forensics").capabilities == []
    assert len(reg.agents()) == 3  # not duplicated


def test_registry_find_resolves_action_to_capability():
    reg = _registry()
    cap = reg.find("forensics", "logs.read")
    assert cap and cap.name == "logs.read"
    # prefix match: a sub-action falls under the advertised capability
    assert reg.find("containment", "net.isolate.host-9").name == "net.isolate"
    assert reg.find("forensics", "fs.write") is None
    assert reg.find("nobody", "logs.read") is None


def test_registry_deregister_drops_the_agent():
    reg = _registry()
    reg.deregister("threat-intel")
    assert "threat-intel" not in reg.agents()


# ── deterministic matcher ────────────────────────────────────────────────────


def test_matcher_ranks_the_relevant_capability_first():
    m = DeterministicMatcher()
    res = m.match("isolate the compromised host db-prod-12", _registry().capabilities())
    assert isinstance(res, MatchResult)
    assert res.backend == "deterministic"
    assert res.best is not None
    assert res.best.capability.name == "net.isolate"
    # ranked descending by score
    assert [r.score for r in res.ranked] == sorted((r.score for r in res.ranked), reverse=True)


def test_matcher_proposes_a_target_scoped_least_privilege_grant():
    m = DeterministicMatcher()
    res = m.match("isolate the compromised host db-prod-12", _registry().capabilities())
    prop = res.proposal
    assert prop and prop.agent == "containment" and prop.capability == "net.isolate"
    assert prop.scope == {"target": "db-prod-12"}      # id-looking token extracted
    assert prop.excludes == []                          # mutating requirement, no read-only lock
    assert prop.ttl == 300


def test_matcher_locks_out_mutating_verbs_for_read_only_requirements():
    m = DeterministicMatcher()
    res = m.match("read and inspect the auth logs", _registry().capabilities())
    prop = res.proposal
    assert prop and prop.capability == "logs.read"
    # read-only intent → mutating verbs explicitly excluded (defense in depth)
    assert "write" in prop.excludes and "delete" in prop.excludes
    assert "read-only" in prop.rationale


def test_matcher_returns_no_proposal_when_nothing_matches():
    m = DeterministicMatcher()
    res = m.match("provision a kubernetes cluster", [])  # empty registry
    assert res.ranked == [] and res.proposal is None and res.best is None


# ── gateway integration ──────────────────────────────────────────────────────


def test_gateway_match_uses_the_registry_then_a_warrant_can_be_issued():
    gw = Gateway()
    gw.register_agent("containment", trust="internal", capabilities=ROSTER["containment"])
    gw.register_agent("forensics", trust="internal", capabilities=ROSTER["forensics"])

    res = gw.match("isolate the compromised host host-9", on_behalf_of="incident://ir-1")
    prop = res.proposal
    assert prop.agent == "containment" and prop.scope == {"target": "host-9"}

    # The proposal is advisory — issuing is still explicit. Feed it through verbatim.
    ident = gw._identities["containment"]
    w = gw.issue_warrant(
        subject=prop.agent, on_behalf_of="incident://ir-1",
        capability=prop.capability, scope=prop.scope, excludes=prop.excludes, ttl=prop.ttl,
    )
    assert w.subject == ident.id
    assert gw.enforce(ToolCall(agent=ident.id, action="net.isolate", target="host-9")).allow


def test_gateway_registration_without_capabilities_still_issues_identity_only():
    gw = Gateway()
    gw.register_agent("plain")  # no capabilities advertised
    assert "plain" not in gw.registry.agents()   # nothing in the registry
    assert "plain" in gw._identities             # but it has an identity


def test_snapshot_lists_registered_agents():
    gw = Gateway()
    gw.register_agent("containment", capabilities=ROSTER["containment"])
    assert gw.snapshot()["agents"] == ["containment"]
