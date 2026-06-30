"""M9/M10: the orchestrator-driven Phase-2 scenarios.

Unlike a hand-scripted replay, here the orchestrator *decides* the swaps. These tests
pin that the team reshapes for real — via perf and budget triggers — that the gateway
cuts off whoever was dropped, and that every Phase-1 invariant (least-privilege, scope,
capability) still holds on an orchestrator-selected agent.
"""

from typer.testing import CliRunner

from praetor.cli import app
from praetor.scenarios import (
    SCENARIOS,
    Phase2CrossFramework,
    Phase2LeastPrivilege,
    Phase2WarRoom,
)

runner = CliRunner()


def _verdicts(frames):
    return [(f.message.split(" · ")[1].split("(")[0], f.badge)
            for f in frames if f.badge in ("ALLOW", "DENY")]


def test_phase2_scenarios_are_registered():
    assert SCENARIOS["phase2-war-room"] is Phase2WarRoom
    assert SCENARIOS["phase2-least-privilege"] is Phase2LeastPrivilege
    assert SCENARIOS["phase2-cross-framework"] is Phase2CrossFramework


# ── phase2-war-room: perf swap + budget gate ─────────────────────────────────


def test_phase2_war_room_reshapes_via_orchestrator_decisions():
    gw, frames = Phase2WarRoom().run()
    assert _verdicts(frames) == [
        ("net.isolate", "ALLOW"),   # best-fit containment admitted, acts
        ("net.isolate", "DENY"),    # benched after underperformance
        ("net.isolate", "ALLOW"),   # promoted next-best takes over
        ("logs.read", "ALLOW"),     # trusted forensics admitted under budget headroom
        ("logs.read", "ALLOW"),     # cheaper forensics after the budget gate
    ]
    causes = [e.cause for e in gw.audit.entries() if e.kind == "revoke"]
    assert "perf" in causes


def test_phase2_war_room_admits_a_different_agent_after_each_trigger():
    _, frames = Phase2WarRoom().run()
    admits = [f.message.split(" · ")[1] for f in frames if f.badge == "ISSUE"]
    assert admits[0] == "containment-a"
    assert admits[1] == "containment-b"
    assert "forensics-pro" in admits and "forensics-lite" in admits


# ── phase2-least-privilege: orchestrator picks, warrant still contains ────────


def test_phase2_least_privilege_denies_write_on_the_admitted_agent():
    gw, frames = Phase2LeastPrivilege().run()
    assert _verdicts(frames) == [
        ("db.read", "ALLOW"),    # admitted agent reads
        ("db.write", "DENY"),    # write-capable, but read-only warrant → denied
        ("db.read", "ALLOW"),    # cheaper agent after budget gate
        ("db.write", "DENY"),    # still contained
    ]
    # the trusted-but-pricier agent wins first, then the budget gate swaps it out
    admits = [f.message.split(" · ")[1] for f in frames if f.badge == "ISSUE"]
    assert admits == ["postgres-primary", "postgres-lite"]
    assert "phase" in [e.cause for e in gw.audit.entries() if e.kind == "revoke"]


# ── phase2-cross-framework: best-fit selection across stacks ─────────────────


def test_phase2_cross_framework_picks_and_swaps_across_frameworks():
    gw, frames = Phase2CrossFramework().run()
    assert _verdicts(frames) == [
        ("web.search", "ALLOW"),     # best-fit researcher (Claude, higher trust)
        ("web.search", "DENY"),      # benched after underperformance
        ("web.search", "ALLOW"),     # rival framework (OpenAI) promoted
        ("doc.write", "ALLOW"),      # Claude drafter, scoped
        ("doc.write", "DENY"),       # out of scope
        ("ticket.create", "ALLOW"),  # Copilot ticketer
        ("ticket.delete", "DENY"),   # outside capability
    ]
    admits = [f.message.split(" · ")[1] for f in frames if f.badge == "ISSUE"]
    assert admits[0] == "claude-researcher" and admits[1] == "openai-researcher"


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_runs_each_phase2_scenario():
    for key in ("phase2-war-room", "phase2-least-privilege", "phase2-cross-framework"):
        result = runner.invoke(app, ["demo", "--scenario", key])
        assert result.exit_code == 0, key
        assert "ALLOW" in result.stdout and "DENY" in result.stdout
