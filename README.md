# Praetor

**An intelligent gateway that issues scoped, revocable authority — a _warrant_ — to AI
agents, and uses that authority layer to compose and reshape teams of agents.**

> Status: **pre-alpha**, built in the open one increment at a time. The API is unstable
> and will change between commits until the first tagged release.

Praetor sits between a requester and a fluid team of agents. It issues each agent a
**warrant**: a verifiable, least-privilege, time-boxed grant for exactly the capability a
task needs right now — and revokes it the instant you need to. Team membership *is* the set
of valid warrants: admitting an agent means issuing one, dropping it means revoking one.

It is designed to govern a **mix of agents you don't fully control** — ones you build
yourself and third-party agents from popular frameworks (MCP servers, Copilot Studio,
Claude Cowork, ChatGPT, Gemini, or any HTTP endpoint) — behind one uniform adapter and one
enforcement point.

## Why

- **Zero-trust by construction** — an agent can only ever do what it currently holds a
  valid warrant for.
- **Revocation is trivial** — all traffic flows through the gateway, so revoking a warrant
  is just "deny the next call." Effectively instant.
- **Deterministic security, layered intelligence** — identity, scoping, and enforcement are
  crypto and policy (not inference); intelligence is layered on top where non-determinism is
  acceptable.
- **Cheap to run** — the default configuration costs ~$0; paid LLM backends are opt-in.

## Status / roadmap

Built incrementally; each milestone is a commit that installs clean and passes tests.

- **M0** — repo scaffold + CI ✅
- M1 — warrant model + scope matching
- M2 — local keypair identity (RSA-JWT)
- M3 — gateway: issue · enforce · revoke + audit
- M4 — capability registry + deterministic matcher
- M5 — adapter contract + mock adapter + quickstart
- M6 — CLI (`demo`, `match`)
- M7 — FastAPI gateway + Web UI
- M8 — real adapters (HTTP, MCP, Anthropic, OpenAI, Gemini, Copilot Studio)
- M9 — Phase 2 orchestrator (requirement-driven team evolution)
- M10 — pluggable AI backends (local SLM / Claude)

## Develop

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
