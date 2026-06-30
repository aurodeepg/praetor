"""M8: the three new replayable scenarios + the scenario registry.

Like the war room, each drives the *real* gateway — so the tests assert on live
verdicts, not on a script. The point of each scenario is a specific governance claim;
the tests pin that claim.
"""

from typer.testing import CliRunner

from praetor.cli import app
from praetor.scenarios import (
    SCENARIOS,
    CrossFramework,
    LeastPrivilege,
    WarRoom,
)

runner = CliRunner()


def _verdicts(frames):
    """(action, badge) for every enforcement beat, in order."""
    return [(f.message.split(" · ")[1].split("(")[0], f.badge)
            for f in frames if f.badge in ("ALLOW", "DENY")]


# ── registry ─────────────────────────────────────────────────────────────────


def test_registry_exposes_the_m8_scenarios():
    # the M8 scenarios are registered (M9 adds "phase2" on top)
    assert {"war-room", "least-privilege", "cross-framework"} <= set(SCENARIOS)
    assert SCENARIOS["war-room"] is WarRoom


def test_every_scenario_runs_and_produces_live_verdicts():
    for cls in SCENARIOS.values():
        gw, frames = cls().run()
        assert frames, f"{cls.__name__} produced no frames"
        assert any(f.badge == "ALLOW" for f in frames)
        assert any(f.badge == "DENY" for f in frames)
        # every decision beat is recorded in the audit trail
        assert [e for e in gw.audit.entries() if e.kind == "decision"]


# ── #2 least privilege: capable agent, contained by warrant ──────────────────


def test_least_privilege_denies_the_write_even_though_the_agent_can_write():
    gw, frames = LeastPrivilege().run()
    assert _verdicts(frames) == [
        ("db.read", "ALLOW"),    # scoped table
        ("db.read", "DENY"),     # other table → out of scope
        ("db.write", "DENY"),    # capable, but never granted ← the point
        ("db.write", "ALLOW"),   # after a narrow, explicit write grant
        ("db.write", "DENY"),    # after that grant is revoked
    ]
    # the agent genuinely advertises write — containment is the broker's doing, not the agent's
    assert any(
        agent == "analytics" and cap.name == "db.write"
        for agent, cap in gw.registry.capabilities()
    )


# ── #3 cross-framework: three stacks, identical governance ───────────────────


def test_cross_framework_governs_three_frameworks_identically():
    gw, frames = CrossFramework().run()
    assert _verdicts(frames) == [
        ("web.search", "ALLOW"),     # OpenAI researcher, read-only
        ("doc.write", "DENY"),       # researcher can't write
        ("doc.write", "ALLOW"),      # Claude drafter, scoped doc
        ("doc.write", "DENY"),       # drafter out of scope
        ("ticket.create", "ALLOW"),  # Copilot Studio ticketer
        ("ticket.delete", "DENY"),   # outside capability
    ]
    assert {"researcher", "drafter", "ticketer"} <= set(gw.registry.agents())


# ── CLI selects scenarios ────────────────────────────────────────────────────


def test_cli_demo_runs_a_selected_scenario():
    result = runner.invoke(app, ["demo", "--scenario", "least-privilege"])
    assert result.exit_code == 0
    assert "ALLOW" in result.stdout and "DENY" in result.stdout
    assert "contained" in result.stdout.lower()


def test_cli_demo_rejects_an_unknown_scenario():
    result = runner.invoke(app, ["demo", "--scenario", "nope"])
    assert result.exit_code == 2
    assert "unknown scenario" in result.stdout.lower()
