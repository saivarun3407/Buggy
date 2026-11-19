# Phase 0 — UniiChat harness evaluation (2026-11-19)

**Verdict: do not replace, wrap, or integrate UniiChat. Nothing is migrated.**
It is a single-user, single-chat personal assistant whose memory is a lossy
LLM-written summary tree. It has no structured records, no query surface, no
engagement concept, no scope enforcement and no sandbox. It cannot be the
pipeline's data store. Buggy keeps LangGraph + Neo4j for agent reasoning, and
the Phase 2 pipeline gets its own relational recon store (SQLite, see the last
section).

## How this was checked

| Claim | How it was established |
|---|---|
| What UniiChat is, its tools, memory design, storage, HTTP surface, license | **Read from source**: `github.com/VictorTaelin/uniichat` at `0500bf6` (2026-10-19, the repo's only commit), ~12.4k lines of TypeScript. Files read: `README.md`, `Memory.ts`, `Tools.ts`, `Machine.ts`, `Agent.ts`, `Server.ts`, `prompt.txt`. |
| Hosted-service terms | **Read**: `uniichat.com/terms.html` and the landing page. |
| Buggy's orchestration and memory layer | **Read from source** in this repo (file references below). |
| Anything about UniiChat's runtime behaviour | **Not run.** No UniiChat server was started; nothing below is a measured result. |

## What UniiChat provides

- **Product**: "an AI agent with one chat that never ends" (README). One chat
  per signed-in user (`Server.ts` header: "chats that never end, one per user
  signed in"). There is no "new chat", project, or engagement.
- **Memory**: every message is compressed by a cheaper "compactor" model into
  one line of at most 512 bytes; adjacent lines are merged pairwise into a
  binary tree (`Memory.ts` header, `prompt.txt` "Compactions"). Each model call
  sees a view of the whole chat capped at 128 KB. The only retrieval primitive
  is `zoom(id, n)`, which opens a summary line into the two it was made from
  (`Tools.ts:196`). The system prompt forbids any other lookup: "Never grep or
  search memories manually; zoom is your only allowed mechanism".
- **Storage**: JSON-lines files under `~/.unii/users/<id>/`: `main/` (messages)
  and `tree/` (summaries), plus index files and `view.json` (`Memory.ts`
  header). No database.
- **Orchestration**: `spawn(tasks[])` starts background subagents that report
  back as chat messages; `tell(name, message)` messages one (`Tools.ts:200-201`).
  No graph, roles, middleware, budgets, or approval gates.
- **Tools**: `shell`, `read`, `write`, `edit` (`Machine.ts:63-66`), macOS
  `computer` use, `zoom`, `date`, `spawn`, `tell`. `shell` runs `$SHELL -c` on
  the user's own computer. No sandbox or network policy exists in the source.
- **API / SDK**: none. The HTTP routes (`/api/act`, `/api/login`, `/ws`,
  `/export`, …) serve its own browser and terminal clients. It serves its own
  tools to the model over a local MCP port but has no configuration for
  external MCP servers.
- **Licensing / self-hosting**: source is Apache-2.0 (`LICENSE`, "Copyright
  2026 Higher Order Company"). Self-host with `bun Server.ts` on your own
  Anthropic or OpenAI key. The hosted service's terms state "Your uploads may
  leak. Keep secrets out." and "Served as is. No guarantees."; the README says
  "This repo is vibe-coded … expect bugs."

## Comparison with Buggy

| Capability | Buggy today | UniiChat |
|---|---|---|
| Orchestration | 20 LangGraph graphs (`langgraph.json`), per-role middleware slots (`buggy_core/contracts/slots.py`), subagents via deepagents `task()`, coordinator registry + mailbox (`middleware/coordinator.py`) | `spawn` / `tell` only |
| Engagement scoping | Every KG read/write requires `$engagement` (`kg_internal/store.py:182-225`) | None; one chat per user |
| Structured records | Typed nodes/edges, unique on `(key, engagement)` (`kg_internal/migrations/V001`) | None; free text |
| Query | Cypher via `kg_query` | `zoom` into a summary line |
| Provenance | `created_by`, `source_episode_id`, timestamps, immutable `:Evidence` with SHA-256 of raw tool output (`store.py:241-284`) | Lossy summary; originals reachable only by zooming |
| Scope / RoE enforcement | RoE middleware + egress policy (repaired in Phase 1) | None |
| Sandbox | Dedicated container | Shell on the user's machine |
| Finding lifecycle | Proof gate → candidate → corroboration gate → published | None |
| Runtime | Python | TypeScript on Bun |

## Can it be the single data store for pipeline output?

No. Each requirement fails on source evidence:

- **Structured records** — it stores chat messages and summary lines only.
- **Queryable by engagement and asset** — there is no index or query; lookup is
  a model-driven walk down a summary tree, and the product has no engagement.
- **Provenance** — a summary is written by an LLM and capped at 512 bytes; the
  compaction prompt itself says "what your line omits is lost for good" unless
  the agent zooms to the original. That is not an auditable record.
- **Deterministic access** — reading it requires an LLM call, which contradicts
  the rule that deterministic work never goes to an agent.

## Recommendation

1. **Replace** — no. It would remove engagement scoping, the KG, the finding
   gates, the sandbox and RoE enforcement, and move the stack to another
   language.
2. **Wrap** — no. There is no API or SDK to wrap.
3. **Integrate as memory layer only** — no. Its memory is conversational recall
   for one endless chat, not a store of engagement facts.

The one idea worth keeping in mind is the summary tree as a way to keep long
agent transcripts in context without destructive compaction. That is a possible
later change to Buggy's summarisation middleware, not part of this work.

## Gaps found in Buggy's own memory layer while comparing

All three were fixed afterwards and checked on a running stack:

- Migrations: applied at first use (`ensure_schema`). On a fresh Neo4j the
  constraint count went from 0 to 53.
- `created_by`: the KG middleware passes its agent role to the tools.
- Thread state: the runtime already flushed to `/app/.langgraph_api`; it was
  lost only when the container was recreated. A named volume is mounted
  there now, and a thread survived a forced recreation.

As originally found:

- KG migrations are never applied at runtime; `apply_migrations()` is only
  called from tests (`kg_internal/migration_runner.py:74`), so the uniqueness
  constraints and indexes do not exist on a fresh stack.
- `created_by` on KG writes falls back to `"agent"` because no state schema
  declares `role` / `agent_name` (`kg_internal/tools.py:78-87`).
- The `langgraph` service runs `langgraph dev` with the in-memory runtime, so
  agent thread state does not survive a container restart.

## Decision for Phase 2

Pipeline output goes to a **SQLite recon store** owned by the pipeline:
one normalised table keyed by engagement and asset, with source tool,
timestamp and a raw-output reference on every row, plus run and diff tables.
It lives in a volume mounted only into the pipeline and its read-only MCP
server, so agents can query it but cannot write to it. Neo4j remains the
agents' reasoning memory (hypotheses, chains, findings).
