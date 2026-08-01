# Third-party agents to test Praetor against

Praetor's claim is that it governs agents **you don't own and don't trust**. That claim
is only worth anything if you can point it at real ones. This is a shortlist of agents
and tool surfaces available online, ordered by how much friction it takes to get going.

The governance property is the same for every entry: the gateway decides ALLOW *before*
`invoke`, so a denied call never reaches the agent. What varies is only the adapter.

> Availability, free tiers, and model rosters on third-party services change without
> notice. Everything below was checked in **August 2026** — re-verify before relying on
> it for a demo.

---

## Tier 0 — no account, no key, $0

The best place to start: these run entirely on your machine and prove the enforcement
story without a single credential.

| Agent | Adapter | How |
| --- | --- | --- |
| **Praetor's own FastMCP server** | `MCPAdapter` | `python examples/connect_mcp.py` — bundled, offline, runs the full issue → dispatch → deny → revoke loop |
| **Filesystem MCP** (`@modelcontextprotocol/server-filesystem`) | `MCPAdapter` | `python examples/connect_mcp.py -- npx -y @modelcontextprotocol/server-filesystem /tmp` |
| **Playwright MCP** (`microsoft/playwright-mcp`) | `MCPAdapter` | `python examples/connect_mcp.py -- npx -y @playwright/mcp@latest` — a browser-driving agent with genuinely dangerous reach |
| **Ollama** (any local model) | `OpenAIAdapter` | Point `base_url` at `http://localhost:11434/v1` — Ollama serves the OpenAI chat-completions shape |
| **LM Studio / vLLM / llama.cpp** | `OpenAIAdapter` | Same: any server speaking `/v1/chat/completions` works by changing `base_url` |

Playwright MCP is the most persuasive of these for a demo — the agent can genuinely
navigate, click, and fill forms, and you can watch the gateway allow `browser.navigate`
while denying `browser.file_upload` on the *same* agent.

## Tier 1 — free account, no card

| Agent | Adapter | Notes |
| --- | --- | --- |
| **OpenRouter free models** (`:free` model ids) | `OpenAIAdapter` | `base_url="https://openrouter.ai/api/v1"`. Usable at a $0 balance with no credit card; rate-limited (~20 req/min). **The free roster rotates with little notice** — check the current list rather than hard-coding a model id |
| **Google Gemini free tier** | `GeminiAdapter` | `GEMINI_API_KEY` from AI Studio; native `generateContent`. Also serves an OpenAI-compatible endpoint if you'd rather use `OpenAIAdapter` |
| **Read-only Postgres MCP** (`@modelcontextprotocol/server-postgres`) | `MCPAdapter` | Needs a database, not an account. Useful because the *server* self-limits to read-only — Praetor's point is that the warrant constrains it regardless |

## Tier 2 — paid key

| Agent | Adapter |
| --- | --- |
| **OpenAI / ChatGPT models** | `OpenAIAdapter` |
| **Anthropic / Claude models** | `AnthropicAdapter` |
| **GitHub MCP, Sentry, Datadog, Grafana, PagerDuty** | `MCPAdapter` |
| **Supabase MCP** (`@supabase/mcp-server-supabase`) | `MCPAdapter` — see the caveat below |
| **Microsoft Copilot Studio agent** | `CopilotStudioAdapter` — needs a Copilot Studio tenant and a Direct Line secret |

**Sharpens the pitch:** several of these default to **read *and* write** (PagerDuty
hosted, many Postgres servers, Supabase). That is exactly Praetor's argument — the
gateway issues a narrow warrant *regardless of what the agent is technically capable
of*, and it does so at the broker, without the agent's cooperation.

---

## Known gap: argument-level policy

`warrant_authorizes` decides on the **action name**, an **exclude-list**, and a single
**`target` glob**. It does not inspect `call.args`.

For a filesystem server that is enough (`read_file` + `target=logs/*`). For **Supabase**
it is not: the danger lives inside one capability, `execute_sql`, whose payload is
arbitrary SQL in the `query` argument. `SELECT count(*)` and `DROP TABLE auth.users` are
the same action with no target to bite on, so least-privilege collapses to "allow
`execute_sql`" or "deny it entirely."

Treat any agent whose power is concentrated in a single free-form argument as **not yet
fully governable** by Praetor. Argument-level policy is the open design item.

Two more Supabase-specific cautions if you test against it anyway: a Supabase personal
access token is **account-scoped, not project-scoped** (`--project-ref` scopes the
server, not the token), and `npx` runs unvetted third-party code with that token.

---

## What to actually demonstrate

Pointing an adapter at a real agent is the setup, not the payoff. The payoff is making
the consequence visible:

1. Register the agent and let it do the one thing it is warranted for.
2. Have it attempt a **second capability it genuinely has** — and watch the gateway deny
   it before the call leaves the process.
3. Revoke the warrant mid-session and watch the next call get cut off.
4. Show the audit trail binding every decision to an identity and the warrant that
   authorized it.

Step 2 is the one that matters. Denying an agent something it *couldn't do anyway*
proves nothing; denying a capable agent is the whole thesis.
