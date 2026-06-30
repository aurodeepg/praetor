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

## Quickstart

Requires Python 3.10+.

```bash
git clone https://github.com/aurodeepg/praetor.git
cd praetor
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .                                     # core install — no heavy deps

praetor demo                  # replay the incident-response war room (every verdict is live)
praetor match "isolate the compromised host host-9"   # capability matcher → proposed warrant
praetor compose "read the auth logs"                  # Phase-2 orchestrator → team-fit ranking
python examples/quickstart.py # the whole Phase-1 loop: issue → invoke → deny → revoke → audit
```

### Scenarios

`praetor demo --scenario <key>` (or pick one in the Web UI):

| key | what it shows |
| --- | --- |
| `war-room` _(default)_ | mixed-trust incident response; scope, escalation-blocked, revoke, TTL expiry |
| `least-privilege` | a read+write-capable agent held to a read-only warrant — the broker decides, not the agent |
| `cross-framework` | OpenAI + Claude + Copilot Studio agents, governed identically |
| `phase2` | the **orchestrator** reshapes the team itself — perf-based swap + budget gate |

### Web UI

```bash
pip install -e ".[serve]"     # FastAPI + uvicorn
praetor serve                 # → http://localhost:8088  (live ledger + decision feed; pick a scenario)
```

### Semantic matcher (optional, hybrid — local or any API)

By default the capability-matcher is **deterministic** ($0, offline, lexical). You can
opt into a **semantic** backend that ranks capabilities by embedding similarity and
(optionally) drafts the scope proposal with a small generator — it **degrades back to
deterministic** automatically if a model isn't reachable, so nothing ever hard-fails.

It's provider-neutral and split into two independent axes you can mix freely:

- **Embedder** (ranking) and **Generator** (scope proposal), each either **`ollama`**
  (local/offline) or **`openai`** (any OpenAI-compatible endpoint — OpenAI, Gemini's
  compatible API, local servers — via `OPENAI_BASE_URL` + `OPENAI_API_KEY`).

Selection is env-driven; only the HTTP client is needed locally (`pip install -e ".[semantic]"`):

```bash
ollama pull qwen3-embedding:0.6b     # embedder
ollama pull qwen3:0.6b               # generator
export PRAETOR_EMBEDDER="ollama:qwen3-embedding:0.6b"
export PRAETOR_GENERATOR="ollama:qwen3:0.6b"     # optional; omit to keep deterministic proposals
praetor match "isolate the compromised host host-9"   # the printed `backend:` shows which is active
```

**Reference local demo — asymmetric quantization** (Apple Silicon, ~1 GB total):

| Role | Model | Quant | ~Size | Why |
| --- | --- | --- | --- | --- |
| Embedder | `qwen3-embedding:0.6b` | **Q8** | ~639 MB | protect ranking quality; cheap anyway |
| Generator | `qwen3:0.6b` | **Q4** | ~400 MB | tolerable for extraction + constrained decoding |

The embedder drives the headline "semantic" win, so keep it at Q8; the generator only
does narrow scope extraction, so Q4 (with JSON-constrained output) is fine. Mix and match:
a local embedder with a paid generator, or vice versa — same contract, no provider lock-in.

### Run the tests

```bash
pip install -e ".[dev]"
pytest        # and: ruff check .
```

### Optional extras

The core install is deliberately dependency-light; heavier pieces are opt-in and imported lazily.

| extra | adds | for |
| --- | --- | --- |
| `dev` | pytest, ruff, httpx, mcp | running the test suite |
| `serve` | fastapi, uvicorn | the HTTP API + Web UI (`praetor serve`) |
| `http` | httpx | governing a remote agent over HTTP (`HTTPAdapter`) |
| `mcp` | mcp | governing any Model Context Protocol server (`MCPAdapter`) |
| `semantic` | httpx | semantic matcher backends (Ollama / OpenAI-compatible) |

Install several at once, e.g. `pip install -e ".[dev,serve]"`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
