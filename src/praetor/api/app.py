"""FastAPI app — the same gateway behind a REST + WebSocket API and the Web UI.

`praetor serve` runs this. It exposes:

* a REST surface (issue / revoke / enforce / match / inspect) over one live gateway,
  seeded with the war-room roster so it's useful out of the box;
* a WebSocket (`/api/ws/demo`) that streams live war-room frames to the Web UI; and
* the Web UI itself, served from `praetor/web/static`.

Verdicts are produced by the real gateway. The token is never serialized out.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from praetor import __version__
from praetor.gateway import Gateway
from praetor.models import ToolCall
from praetor.scenarios import SCENARIOS
from praetor.scenarios.seed import seed_war_room_agents

STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"


# ── request bodies ──────────────────────────────────────────────────────────
class IssueBody(BaseModel):
    subject: str
    on_behalf_of: str = "incident://demo"
    capability: str
    scope: dict[str, str] = Field(default_factory=dict)
    excludes: list[str] = Field(default_factory=list)
    ttl: float | None = None
    trust: str = "unverified"
    reason: str = ""


class RevokeBody(BaseModel):
    cause: str = "manual"
    reason: str = ""


class EnforceBody(BaseModel):
    agent: str
    action: str
    target: str | None = None
    args: dict = Field(default_factory=dict)


class MatchBody(BaseModel):
    requirement: str
    on_behalf_of: str = ""


def create_app() -> FastAPI:
    app = FastAPI(title="Praetor Gateway", version=__version__)
    gw = Gateway()
    seed_war_room_agents(gw)  # a usable roster the moment the server starts
    app.state.gateway = gw

    # ── REST ──────────────────────────────────────────────────────────────────
    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/agents")
    def agents() -> list[dict]:
        return [m.model_dump() for m in gw.registry.all()]

    @app.get("/api/warrants")
    def warrants() -> list[dict]:
        now = gw.now()
        return [{**w.model_dump(exclude={"token"}), "remaining": w.remaining(now)}
                for w in gw.active_warrants()]

    @app.post("/api/warrants")
    def issue(body: IssueBody) -> dict:
        w = gw.issue_warrant(
            subject=body.subject, on_behalf_of=body.on_behalf_of,
            capability=body.capability, scope=body.scope, excludes=body.excludes,
            ttl=body.ttl, trust=body.trust, reason=body.reason,
        )
        return w.model_dump(exclude={"token"})

    @app.post("/api/warrants/{wid}/revoke")
    def revoke(wid: str, body: RevokeBody) -> JSONResponse:
        w = gw.revoke(wid, cause=body.cause, reason=body.reason)  # type: ignore[arg-type]
        if not w:
            return JSONResponse(
                {"ok": False, "error": "unknown or already-revoked warrant"}, status_code=404
            )
        return JSONResponse({"ok": True, "warrant": w.model_dump(exclude={"token"})})

    @app.post("/api/enforce")
    def enforce(body: EnforceBody) -> dict:
        return gw.enforce(ToolCall(**body.model_dump())).model_dump()

    @app.post("/api/match")
    def match(body: MatchBody) -> dict:
        return gw.match(body.requirement, on_behalf_of=body.on_behalf_of).model_dump()

    @app.get("/api/audit")
    def audit(limit: int = 50) -> list[dict]:
        return [e.model_dump() for e in gw.audit.entries(limit=limit)]

    @app.get("/api/snapshot")
    def snapshot() -> dict:
        return gw.snapshot()

    @app.get("/api/scenarios")
    def scenarios() -> list[dict]:
        """The replayable scenarios the demo WebSocket can stream (incl. the Phase-2
        orchestrator-driven one)."""
        return [{"key": k, "title": cls.title} for k, cls in SCENARIOS.items()]

    # ── WebSocket: live scenario frames ─────────────────────────────────────────
    @app.websocket("/api/ws/demo")
    async def demo(ws: WebSocket) -> None:
        await ws.accept()
        interval = max(0.05, int(ws.query_params.get("interval_ms", "900")) / 1000)
        loop = ws.query_params.get("loop", "1") != "0"
        cls = SCENARIOS.get(ws.query_params.get("scenario", "war-room"))
        if cls is None:
            await ws.send_json({"error": "unknown scenario"})
            await ws.close()
            return
        try:
            while True:  # replay the chosen scenario on its own gateway, continuously
                for frame in cls().play():
                    await ws.send_json(frame.model_dump())
                    await asyncio.sleep(interval)
                if not loop:
                    break
                await asyncio.sleep(interval * 2)
            await ws.close()
        except WebSocketDisconnect:
            return

    # ── Web UI ──────────────────────────────────────────────────────────────────
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    return app


app = create_app()
