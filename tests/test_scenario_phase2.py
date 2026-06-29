"""M9: the orchestrator-driven Phase-2 scenario.

Unlike the hand-scripted `recompose`, here the orchestrator *decides* the swaps. The
test pins that the team reshapes for real — via perf and budget triggers — and that the
gateway cuts off whoever was dropped.
"""

from typer.testing import CliRunner

from praetor.cli import app
from praetor.scenarios import SCENARIOS, Phase2

runner = CliRunner()


def _verdicts(frames):
    return [(f.message.split(" · ")[1].split("(")[0], f.badge)
            for f in frames if f.badge in ("ALLOW", "DENY")]


def test_phase2_is_registered():
    assert SCENARIOS["phase2"] is Phase2


def test_phase2_team_reshapes_via_orchestrator_decisions():
    gw, frames = Phase2().run()
    # the live verdicts: incumbent acts, benched one denied, promoted one acts, etc.
    assert _verdicts(frames) == [
        ("net.isolate", "ALLOW"),   # best-fit containment admitted, acts
        ("net.isolate", "DENY"),    # benched after underperformance
        ("net.isolate", "ALLOW"),   # promoted next-best takes over
        ("logs.read", "ALLOW"),     # trusted forensics admitted under budget headroom
        ("logs.read", "ALLOW"),     # cheaper forensics after the budget gate
    ]
    # both recompositions were real revocations by the orchestrator
    causes = [e.cause for e in gw.audit.entries() if e.kind == "revoke"]
    assert "perf" in causes  # underperformance swap


def test_phase2_admits_a_different_agent_after_each_trigger():
    _, frames = Phase2().run()
    admits = [f.message.split(" · ")[1] for f in frames if f.badge == "ISSUE"]
    # containment-a admitted, then containment-b (perf swap), then forensics-pro,
    # then forensics-lite (budget gate) — four distinct admissions, three distinct names
    assert admits[0] == "containment-a"
    assert admits[1] == "containment-b"
    assert "forensics-pro" in admits and "forensics-lite" in admits


def test_cli_runs_the_phase2_scenario():
    result = runner.invoke(app, ["demo", "--scenario", "phase2"])
    assert result.exit_code == 0
    assert "ALLOW" in result.stdout and "DENY" in result.stdout
    assert "reshapes itself" in result.stdout.lower()
