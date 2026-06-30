"""M9: the Phase-2 orchestrator — the gateway decides team composition.

Fit is deterministic (capability × trust × budget × availability), so these tests pin
the exact ranking and the two headline recomposition triggers from the public vision:
"an agent underperforms and gets swapped" and "a budget gate promotes a cheaper
specialist". Every warrant is issued/revoked through the real gateway.
"""

from praetor.gateway import Gateway
from praetor.models import Capability
from praetor.orchestrator import AgentProfile, Orchestrator, default_trust_weight, score_fit

ISOLATE = Capability(name="net.isolate", description="Quarantine a host", targets="host:*")
READLOGS = Capability(name="logs.read", description="Read system and application logs",
                      targets="logs:*")


def _gw_with(*agents: tuple[str, list[Capability]]) -> Gateway:
    gw = Gateway()
    for name, caps in agents:
        desc = " ".join(c.description for c in caps)
        gw.register_agent(name, capabilities=caps, description=desc)
    return gw


# ── the fit score (pure) ─────────────────────────────────────────────────────


def test_trust_label_maps_to_a_deterministic_weight():
    assert default_trust_weight("internal · high-priv") == 1.0
    assert default_trust_weight("3rd-party · prob.") == 0.4
    assert default_trust_weight("untrusted") == 0.3
    assert default_trust_weight("unverified") == 0.5


def test_any_zero_factor_zeroes_the_fit():
    base = AgentProfile(agent="a", trust="internal", cost=1.0)
    assert score_fit("a", "x", 0.8, base, budget=10).score > 0
    # unavailable → 0
    benched = AgentProfile(agent="a", trust="internal", available=False)
    assert score_fit("a", "x", 0.8, benched, budget=10).score == 0
    # priced out → 0
    pricey = AgentProfile(agent="a", trust="internal", cost=99)
    assert score_fit("a", "x", 0.8, pricey, budget=10).score == 0
    # no capability match → 0
    assert score_fit("a", "x", 0.0, base, budget=10).score == 0


# ── composition: pick the best fit and issue a least-privilege warrant ───────


def test_compose_admits_the_best_fit_and_issues_a_scoped_warrant():
    gw = _gw_with(("containment-a", [ISOLATE]), ("containment-b", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.set_profile(AgentProfile(agent="containment-a", trust="internal", cost=1.0))
    orch.set_profile(AgentProfile(agent="containment-b", trust="internal", cost=2.0))

    comp = orch.compose("isolate the compromised host host-9", on_behalf_of="incident://1")
    # equal trust + capability → cheaper wins the tie-break
    assert comp.chosen == "containment-a"
    assert comp.warrant_id is not None
    # the issued warrant is least-privilege: scoped to the target the matcher extracted
    w = next(w for w in gw.active_warrants() if w.wid == comp.warrant_id)
    assert w.capability == "net.isolate" and w.scope.get("target") == "host-9"


def test_compose_reports_no_viable_agent_when_nothing_fits():
    gw = _gw_with(("containment-a", [ISOLATE]))
    orch = Orchestrator(gw, budget=0.0)
    orch.set_profile(AgentProfile(agent="containment-a", trust="internal", cost=5.0))  # priced out
    comp = orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert comp.chosen is None and "no viable" in comp.note


# ── trigger #1: underperformance → swap ──────────────────────────────────────


def test_underperformance_benches_the_agent_and_promotes_the_next_best():
    gw = _gw_with(("containment-a", [ISOLATE]), ("containment-b", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.set_profile(AgentProfile(agent="containment-a", trust="internal", cost=1.0))
    orch.set_profile(AgentProfile(agent="containment-b", trust="internal", cost=2.0))

    first = orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert first.chosen == "containment-a"

    swaps = orch.report_performance("containment-a", ok=False)  # one failure trips threshold
    assert len(swaps) == 1 and swaps[0].chosen == "containment-b"

    # a's warrant is gone (revoked perf); b now holds the live warrant for the task
    holders = {w.subject for w in gw.active_warrants()}
    assert gw.subject_for("containment-b") in holders
    assert gw.subject_for("containment-a") not in holders
    causes = [e.cause for e in gw.audit.entries() if e.kind == "revoke"]
    assert "perf" in causes


def test_a_single_success_does_not_swap():
    gw = _gw_with(("containment-a", [ISOLATE]), ("containment-b", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.set_profile(AgentProfile(agent="containment-a", trust="internal", cost=1.0))
    orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert orch.report_performance("containment-a", ok=True) == []


# ── trigger #2: budget gate → cheaper specialist ─────────────────────────────


def test_budget_gate_promotes_a_cheaper_specialist():
    gw = _gw_with(("forensics-pro", [READLOGS]), ("forensics-lite", [READLOGS]))
    orch = Orchestrator(gw, budget=10.0)
    # pro is more trusted (wins when affordable) but pricey; lite is cheaper, lower trust
    orch.set_profile(
        AgentProfile(agent="forensics-pro", trust="internal", trust_weight=1.0, cost=5.0))
    orch.set_profile(
        AgentProfile(agent="forensics-lite", trust="internal", trust_weight=0.8, cost=1.0))

    first = orch.compose("read the auth logs", on_behalf_of="incident://1")
    assert first.chosen == "forensics-pro"

    swaps = orch.set_budget(3.0)  # pro (cost 5) is now priced out
    assert len(swaps) == 1 and swaps[0].chosen == "forensics-lite"
    holders = {w.subject for w in gw.active_warrants()}
    assert gw.subject_for("forensics-lite") in holders
    assert gw.subject_for("forensics-pro") not in holders


# ── release a finished phase/task ────────────────────────────────────────────


def test_release_revokes_the_whole_team_for_a_task():
    gw = _gw_with(("containment-a", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.set_profile(AgentProfile(agent="containment-a", trust="internal"))
    orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert gw.active_warrants()
    orch.release("incident://1", cause="phase", reason="phase complete")
    assert gw.active_warrants() == []


# ── profile sync + snapshot (M9 polish) ──────────────────────────────────────


def test_sync_profiles_pulls_trust_from_the_gateway():
    gw = Gateway()
    gw.register_agent("forensics", trust="internal · read-only", capabilities=[READLOGS])
    gw.register_agent("intel", trust="3rd-party · prob.", capabilities=[READLOGS])
    orch = Orchestrator(gw)
    orch.sync_profiles_from_gateway()
    assert orch.profile("forensics").trust == "internal · read-only"
    assert orch.profile("forensics").weight() == 1.0
    assert orch.profile("intel").weight() == 0.4  # third-party → lower


def test_snapshot_exposes_profiles_and_the_last_ranking():
    gw = _gw_with(("containment-a", [ISOLATE]), ("containment-b", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.sync_profiles_from_gateway()
    orch.compose("isolate host-9", on_behalf_of="incident://1")
    snap = orch.snapshot()
    assert set(snap["profiles"]) >= {"containment-a", "containment-b"}
    ranking = snap["rankings"]["incident://1"]
    assert ranking and {"agent", "score", "capability_match", "trust"} <= set(ranking[0])


# ── reputation: trust = declared × earned (M9 polish) ────────────────────────


def test_reputation_biases_composition_toward_the_better_performer():
    gw = _gw_with(("agent-x", [ISOLATE]), ("agent-y", [ISOLATE]))
    orch = Orchestrator(gw)
    # identical except reputation: x has a weaker track record (still available)
    orch.set_profile(AgentProfile(agent="agent-x", trust="internal", cost=1.0, performance=0.7))
    orch.set_profile(AgentProfile(agent="agent-y", trust="internal", cost=1.0, performance=1.0))
    comp = orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert comp.chosen == "agent-y"                  # higher earned trust wins
    assert comp.fit.base_trust == 1.0 and comp.fit.reputation == 1.0
    assert comp.fit.trust == 1.0                     # declared 1.0 × reputation 1.0


def test_rebalance_swaps_to_a_better_reputation_agent():
    gw = _gw_with(("agent-x", [ISOLATE]), ("agent-y", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.set_profile(AgentProfile(agent="agent-x", trust="internal", cost=1.0))
    orch.set_profile(AgentProfile(agent="agent-y", trust="internal", cost=2.0))
    first = orch.compose("isolate host-9", on_behalf_of="incident://1")
    assert first.chosen == "agent-x"                 # cheaper tie-break initially

    orch.profile("agent-x").performance = 0.5        # x's reputation erodes over time
    swap = orch.rebalance("incident://1")
    assert swap is not None and swap.chosen == "agent-y"
    assert "reputation" in [e.cause for e in gw.audit.entries() if e.kind == "revoke"]
    # the incumbent is now best again → no further churn
    assert orch.rebalance("incident://1") is None


# ── preview: read-only ranking, issues nothing ──────────────────────────────


def test_preview_ranks_without_issuing_a_warrant():
    gw = _gw_with(("containment-a", [ISOLATE]))
    orch = Orchestrator(gw)
    orch.sync_profiles_from_gateway()
    comp = orch.preview("isolate host-9", on_behalf_of="incident://1")
    assert comp.chosen == "containment-a" and comp.warrant_id is None
    assert gw.active_warrants() == []                # nothing issued
