"""M7: the FastAPI gateway — REST + WebSocket over the real gateway.

Skips cleanly if the `serve` extra isn't installed (core stays light); CI installs
`.[dev,serve]` so these run there.
"""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from praetor.api.app import create_app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_health_and_seeded_agents(client):
    assert client.get("/api/health").json()["ok"] is True
    agents = client.get("/api/agents").json()
    names = {a["agent"] for a in agents}
    assert {"containment", "forensics", "threat-intel"} <= names


def test_issue_enforce_revoke_lifecycle_over_rest(client):
    # issue a scoped warrant for containment
    issued = client.post("/api/warrants", json={
        "subject": "containment", "capability": "net.isolate",
        "scope": {"target": "host-9"}, "ttl": 300, "reason": "contain",
    }).json()
    wid = issued["wid"]
    assert "token" not in issued                       # never serialized out
    assert wid in {w["wid"] for w in client.get("/api/warrants").json()}

    subject = issued["subject"]
    allow = client.post("/api/enforce", json={
        "agent": subject, "action": "net.isolate", "target": "host-9"}).json()
    assert allow["allow"] is True

    deny = client.post("/api/enforce", json={
        "agent": subject, "action": "net.isolate", "target": "host-other"}).json()
    assert deny["allow"] is False and "scope" in deny["reason"]

    # revoke → the next call is denied
    assert client.post(f"/api/warrants/{wid}/revoke", json={"reason": "done"}).json()["ok"]
    after = client.post("/api/enforce", json={
        "agent": subject, "action": "net.isolate", "target": "host-9"}).json()
    assert after["allow"] is False


def test_revoke_unknown_warrant_is_404(client):
    r = client.post("/api/warrants/w:nope/revoke", json={})
    assert r.status_code == 404 and r.json()["ok"] is False


def test_match_endpoint_proposes_a_scope(client):
    res = client.post("/api/match", json={
        "requirement": "isolate the compromised host host-9"}).json()
    assert res["proposal"]["capability"] == "net.isolate"
    assert res["proposal"]["scope"] == {"target": "host-9"}


def test_audit_and_snapshot(client):
    client.post("/api/warrants", json={"subject": "forensics", "capability": "logs.read"})
    assert any(e["kind"] == "issue" for e in client.get("/api/audit").json())
    snap = client.get("/api/snapshot").json()
    assert "warrants" in snap and "audit" in snap and "agents" in snap


def test_websocket_streams_war_room_frames(client):
    # interval_ms=0 → no server-side pacing delay; loop=0 → finite stream.
    with client.websocket_connect("/api/ws/demo?interval_ms=0&loop=0") as ws:
        first = ws.receive_json()
        assert {"phase", "narration", "badge", "cls", "message", "ledger"} <= set(first)
        badges = {first["badge"]}
        for _ in range(11):  # the replay has 12 frames total
            badges.add(ws.receive_json()["badge"])
    # the stream carried both grants and live verdicts
    assert "ISSUE" in badges and "ALLOW" in badges and "DENY" in badges
