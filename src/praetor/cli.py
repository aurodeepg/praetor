"""Praetor CLI — drive the gateway from the terminal.

    praetor demo                      # replay the incident-response war room (Phase 1)
    praetor demo --interval 1.0       # pace the replay for a live audience
    praetor match "isolate host-9"    # capability matcher → proposed least-privilege grant
    praetor version

Every verdict in `demo` comes from the real gateway, not a script.
"""

from __future__ import annotations

import time

import typer
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from praetor import __version__
from praetor.gateway import Gateway
from praetor.scenarios import SCENARIOS
from praetor.scenarios.base import Frame
from praetor.scenarios.seed import seed_war_room_agents

app = typer.Typer(add_completion=False, help="Scoped, revocable authority for AI agent teams.")
console = Console()

_BADGE_STYLE = {
    "gold": "bold yellow", "allow": "bold green", "deny": "bold red",
    "info": "bold cyan", "warn": "bold yellow",
}


# ── demo ──────────────────────────────────────────────────────────────────────
def _render_frame(frame: Frame) -> None:
    console.print(Rule(Text(f" {frame.phase} ", style="bold white on grey23"), align="left"))
    console.print(Text(frame.narration, style="italic"))

    badge = Text(f" {frame.badge} ", style=_BADGE_STYLE.get(frame.cls, "white"))
    line = Text.assemble(badge, "  ", Text(frame.message))
    if frame.reason:
        line.append(f"\n   ↳ {frame.reason}", style="dim")
    console.print(line)

    ledger = Table(title="active warrants", title_style="dim", box=None, pad_edge=False)
    for col in ("agent", "capability", "scope", "trust", "ttl-left"):
        ledger.add_column(col, style="white" if col == "agent" else "dim")
    if not frame.ledger:
        ledger.add_row("—", "no live authority", "", "", "")
    for w in frame.ledger:
        low = w.remaining <= max(1, w.ttl // 3)
        ledger.add_row(w.agent, w.capability, w.scope, w.trust,
                       Text(f"{w.remaining}s", style="red" if low else "green"))
    console.print(ledger)
    console.print()


@app.command()
def demo(
    scenario: str = typer.Option(
        "war-room", "--scenario", "-s",
        help=f"Which scenario to replay. One of: {', '.join(SCENARIOS)}.",
    ),
    interval: float = typer.Option(0.0, "--interval", "-i", help="Seconds to pause between beats."),
    loop: bool = typer.Option(False, "--loop", help="Repeat until interrupted."),
) -> None:
    """Replay a scenario through the real gateway (every verdict is live)."""
    cls = SCENARIOS.get(scenario)
    if cls is None:
        console.print(f"[red]unknown scenario '{scenario}'.[/red] "
                      f"choose one of: {', '.join(SCENARIOS)}")
        raise typer.Exit(code=2)
    console.print(Panel.fit(
        Text(f"PRAETOR · {cls.title}", style="bold"),
        subtitle="every verdict is live, not scripted",
    ))
    try:
        while True:
            for frame in cls().play():
                _render_frame(frame)
                if interval:
                    time.sleep(interval)
            if not loop:
                break
            time.sleep(max(interval, 1.0) * 2)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped.[/dim]")


# ── match ──────────────────────────────────────────────────────────────────────
@app.command()
def match(requirement: str) -> None:
    """Run the capability matcher on a free-form requirement (the single AI touch)."""
    gw = Gateway()
    seed_war_room_agents(gw)
    result = gw.match(requirement)

    console.print(f"[bold]requirement[/bold]: {requirement}")
    console.print(f"[dim]backend: {result.backend}[/dim]\n")
    table = Table("score", "agent", "capability", box=None)
    for r in result.ranked[:5]:
        table.add_row(f"{r.score:.3f}", r.agent, r.capability.name)
    console.print(table)

    if result.proposal:
        p = result.proposal
        console.print(Panel(
            f"[bold]agent[/bold]      {p.agent}\n"
            f"[bold]capability[/bold] {p.capability}\n"
            f"[bold]scope[/bold]      {p.scope or '—'}\n"
            f"[bold]excludes[/bold]   {p.excludes or '—'}\n"
            f"[bold]ttl[/bold]        {p.ttl}s\n"
            f"[dim]{p.rationale}[/dim]",
            title="PROPOSED LEAST-PRIVILEGE WARRANT · awaiting approval",
            border_style="yellow",
        ))
    else:
        console.print("[dim]no capability matched — nothing proposed.[/dim]")


# ── serve ──────────────────────────────────────────────────────────────────────
@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host."),
    port: int = typer.Option(8088, help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (dev)."),
) -> None:
    """Run the gateway HTTP API + Web UI (requires the `serve` extra)."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]The HTTP gateway needs extra deps:[/red] pip install 'praetor[serve]'")
        raise typer.Exit(1) from None
    console.print(
        f"[bold green]Praetor[/bold green] gateway → http://{host}:{port}  (Web UI at /)"
    )
    uvicorn.run("praetor.api.app:app", host=host, port=port, reload=reload)


@app.command()
def version() -> None:
    """Print the Praetor version."""
    console.print(f"praetor {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
