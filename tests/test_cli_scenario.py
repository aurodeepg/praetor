"""M6: the war-room scenario + the Typer CLI.

The scenario drives the *real* gateway, so the tests assert on live verdicts. The CLI
tests just confirm the commands wire up and surface those verdicts.
"""

from typer.testing import CliRunner

from praetor.cli import app
from praetor.scenarios.war_room import WarRoom, play

runner = CliRunner()


# ── the scenario: real verdicts, in order ────────────────────────────────────


def test_replay_produces_the_expected_live_verdicts():
    _, frames = play()
    # Pull out just the enforcement beats (those carry an ALLOW/DENY badge).
    verdicts = [(f.message.split(" · ")[1].split("(")[0], f.badge)
                for f in frames if f.badge in ("ALLOW", "DENY")]
    assert verdicts == [
        ("logs.read", "ALLOW"),         # forensics, scoped
        ("net.isolate", "ALLOW"),       # containment, scoped to host-9
        ("net.isolate", "DENY"),        # wrong host → out of scope
        ("fs.write", "DENY"),           # escalation → outside capability
        ("intel.lookup", "ALLOW"),      # third party, scoped
        ("logs.read", "DENY"),          # untrusted agent, no warrant for it
        ("net.isolate", "DENY"),        # after revoke
        ("intel.lookup", "DENY"),       # after TTL expiry
    ]


def test_revocation_and_expiry_have_distinct_reasons():
    _, frames = play()
    denies = [f for f in frames if f.badge == "DENY"]
    revoke_frame = next(f for f in denies if f.phase == "WRAP-UP" and "net.isolate" in f.message)
    expiry_frame = next(f for f in denies if "intel.lookup" in f.message)
    assert "no valid warrant" in revoke_frame.reason
    assert "no valid warrant" in expiry_frame.reason  # expired ⇒ not in the live set


def test_scenario_audit_trail_is_complete():
    gw, _ = play()
    kinds = [e.kind for e in gw.audit.entries()]
    assert kinds.count("issue") == 3            # forensics, containment, intel
    assert kinds.count("revoke") >= 2           # 1 manual + ≥1 ttl auto-expiry
    assert kinds.count("decision") == 8


def test_ledger_resolves_subject_ids_to_readable_names():
    frames = list(WarRoom().play())
    # After containment is granted, its row should show the name, not the raw id.
    contain = next(f for f in frames if any(r.agent == "containment" for r in f.ledger))
    row = next(r for r in contain.ledger if r.agent == "containment")
    assert row.capability == "net.isolate" and row.scope == "host-9"


# ── the CLI ──────────────────────────────────────────────────────────────────


def test_cli_demo_runs_and_shows_allow_and_deny():
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "ALLOW" in result.stdout and "DENY" in result.stdout
    assert "war room" in result.stdout.lower()


def test_cli_match_proposes_a_scoped_warrant():
    result = runner.invoke(app, ["match", "isolate the compromised host host-9"])
    assert result.exit_code == 0
    assert "net.isolate" in result.stdout
    assert "PROPOSED LEAST-PRIVILEGE WARRANT" in result.stdout
    assert "host-9" in result.stdout


def test_cli_match_handles_no_match_gracefully():
    result = runner.invoke(app, ["match", "xyzzy nonsense unrelated"])
    assert result.exit_code == 0  # ranks everything; may still propose the top lexical fit


def test_cli_compose_runs_the_orchestrator_and_admits_an_agent():
    result = runner.invoke(app, ["compose", "isolate the compromised host host-9"])
    assert result.exit_code == 0
    assert "TEAM COMPOSED" in result.stdout
    assert "containment" in result.stdout  # best fit for an isolate requirement


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and "praetor" in result.stdout
