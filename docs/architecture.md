# Architecture

## Overview

Buggy runs on two Docker networks. Management infrastructure (LLM proxy, databases, agent API) and operational infrastructure (sandbox, C2, targets) are separated so that no offensive tool inside the sandbox can reach the LLM gateway, the API surface, or your credentials over the network. The agent drives the sandbox via the Docker socket, never via TCP.

```
┌──────────────────────────────────────────────────────────────┐
│                     User Interfaces                          │
│          Terminal CLI (Ink)        Web Dashboard (Next.js)   │
└─────────────────────────┬────────────────────────────────────┘
                          │ SSE / LangGraph SDK
┌─────────────────────────▼────────────────────────────────────┐
│                  LangGraph Platform (port 2024)               │
│              Agent Orchestration & Event Streaming            │
└──────────┬───────────────────────────────────────────────────┘
           │                              │ Docker socket only
┌──────────▼──────────┐                   │
│   buggy-net    │       ┌───────────▼──────────────────┐
│                     │       │       sandbox-net            │
│  LiteLLM    :4000   │       │                              │
│  PostgreSQL :5432   │       │  Sandbox (Kali Linux)        │
│  LangGraph  :2024   │       │                              │
│  Web        :3000   │       │  Victim targets              │
│                     │       │                              │
│  Neo4j ◀────────────┼───────┼──▶ Neo4j  :7687/:7474        │
│  (KGStore — dual-homed bolt:// for agent + sandbox writes)  │
│                     │       │                              │
└─────────────────────┘       └──────────────────────────────┘
       Management                       Operations
   (LLM, persistence, UI)        (sandbox, targets)
```

**Network boundaries.** The sandbox cannot reach LiteLLM, PostgreSQL, the LangGraph API or the web dashboard — none of the management services are routable from `sandbox-net`. The agent inside LangGraph cannot reach attack tooling over a TCP socket; the only channel into the sandbox is `docker exec` via the Docker socket bind-mount.

**KGStore Neo4j is the one cross-network shared service** — it sits on both networks because the sandbox writes findings into it (`bolt://neo4j:7687` from inside Kali) and the agent reads them back (`bolt://neo4j:7687` from inside LangGraph). It's a knowledge store, not a privileged service: the agent's credentials never traverse it, and a compromised sandbox can't pivot through Neo4j to LiteLLM or the API surface.

---

## Components

### LiteLLM Proxy (`buggy-net`, port 4000)

Routes all LLM requests to provider backends (Anthropic, OpenAI, Google, MiniMax, DeepSeek, xAI, Mistral, OpenRouter, Nvidia NIM, Ollama, plus 6 subscription OAuth handlers). Provides:
- Unified API endpoint for all agents
- Automatic fallback chain when a provider is unavailable
- Usage tracking and rate limiting per provider
- Billing aggregation across models

Configuration: `config/litellm.yaml`. Dynamic model registration: `config/litellm_dynamic_config.py` (Ollama, custom gateways, ad-hoc overrides).

### LangGraph Platform (`buggy-net`, port 2024)

Hosts and orchestrates all agents. Provides:
- Agent lifecycle management (spawn, execute, terminate)
- Event streaming via Server-Sent Events (SSE)
- State persistence between agent runs
- The LangGraph SDK endpoint consumed by both the CLI and Web Dashboard

### PostgreSQL (`buggy-net`, port 5432)

Persistent relational storage for:
- LiteLLM virtual keys, spend logs, user budgets
- Web dashboard data (engagements, findings, OPPLAN objectives, defense actions)
- The single local user record

Two logical databases: `litellm` (managed by LiteLLM) and `buggy_web` (managed via Prisma in the web dashboard).

### Neo4j Knowledge Graph — KGStore (`sandbox-net` + `buggy-net`, port 7687 / browser 7474)

Graph database for the cross-domain attack graph (web, cloud, smart-contract findings plus the chain planner's view across all domains). Stores:
- Hosts, services, vulnerabilities, credentials, accounts
- Typed relationships (EXPLOITS, REQUIRES, AFFECTS, LEADS_TO)
- Attack chain paths for multi-hop planning

**Dual-homed by design**: the sandbox writes operational findings into the graph (`cypher-shell` from inside Kali), and the agent in LangGraph reads them back to plan the next objective. Both networks see the same Neo4j instance on the same `bolt://neo4j:7687` URI.

### Skillogy (`buggy-net`, REST API on host port 9100)

Standalone skill catalog service introduced by [ADR-0008](adr/0008-skillogy-hard-acl-phase1a.md). Three pieces:

- A `python:3.13-slim`–based container (`containers/skillogy.Dockerfile`) running FastAPI over Uvicorn.
- A dedicated Neo4j graph (separate from the engagement KG above) holding `:Skill` nodes with edges derived from skill frontmatter (`BUILDS_ON`, `CHAINS_TO`, `MITRE_RELATED`, …).
- Three REST endpoints (`POST /v1/skills:find`, `POST /v1/skills:load`, `POST /v1/skills:traverse`) plus health (`GET /v1/health`) and a manager-of-coverage helper (`POST /v1/skills:moc`).

The graph is rebuilt from disk at container start. Skill source remains the `packages/buggy/buggy/skills/` directory tree (`standard/`, `shared/`, plus `plugins/` from third-party bundles). Adding a skill is a new `SKILL.md` file plus a graph rebuild — no schema migration.

Agents reach Skillogy through `SkillogyMiddleware`, which is a thin REST client. The middleware projects three agent-facing tools onto each role:

- `find_skill(query?, subdomain?, mitre_id?, tag?, tactic_id?, limit=20)` — AND-combined relationship-aware discovery, returns frontmatter only.
- `load_skill(name_or_path)` — fetches the body + frontmatter of one skill.
- `traverse(from_path, edge_types?, depth=2)` — explicit BFS from a seed skill.

Every middleware call carries an `allowed_path_prefixes` parameter set by the agent factory (e.g. `["skills/standard/exploit/", "skills/shared/"]`); Skillogy enforces this hard ACL server-side, so prompt-injected widening attempts cannot escape the role's slice. Cross-role reads only succeed when the target lives under `skills/shared/`.

The Neo4j instance Skillogy uses is **not** the same as the engagement KGStore — they have different schemas, different write semantics, and run as separate containers so a long catalog rebuild can't lock engagement reads.

### Sandbox (`sandbox-net`)

Hardened Kali Linux container. Runs:
- All agent-issued bash commands (via persistent tmux sessions)
- Offensive tools: nmap, sqlmap, Impacket, Metasploit, Nuclei
- Interactive sessions for tools like `msfconsole`, `evil-winrm`

The sandbox is the only place where commands actually execute. LangGraph reaches it via the Docker socket, not the network.

### Web Dashboard (`buggy-net`, port 3000 + terminal WebSocket on 3003 — dynamic-spawn)

Next.js 16 application providing a browser-based control plane. v1.1.8 made this dynamic: it no longer comes up on `buggy start`. From inside the CLI, run `/web` to spawn it; `/web url` prints the URL; `/web down` stops the container without removing it. See [Web Dashboard](web-dashboard.md).

---

## Bash Tool & Interactive Sessions

Agents execute commands through a thin `bash` tool backed by `DockerSandbox.execute_tmux()`. Key behaviors:

**Persistent tmux sessions** — each named session persists across commands. An agent can open `msfconsole`, send commands into the session, and read output — the same way a human operator would.

**Interactive prompt detection** — when a tool presents an interactive prompt (`msf6 >`, `sliver >`, `PS C:\>`), the agent detects it and sends follow-up commands rather than waiting forever.

**Output management:**

| Output size | Handling |
|-------------|---------|
| ≤ 15K chars | Returned inline in the tool result |
| 15K – 100K chars | Saved to `/workspace/.scratch/`, summary returned |
| > 5M chars | Watchdog kills the command |

ANSI escape codes are stripped and repetitive output lines are compressed before being sent to the LLM.

**Background commands + auto-notification** — long-running commands (`nmap -p- -A`, full Burp scans, fuzzers) launch with `run_in_background=True` and return immediately with a session handle. The LLM doesn't block on the prompt while the command runs. When the command finishes, `SandboxNotificationMiddleware` (in `packages/buggy/buggy/middleware/notifications.py`) polls the sandbox's `/read_session_log_diff` once per turn, captures the new output, and injects a `<system-reminder>` `HumanMessage` carrying the exit code and stdout/stderr diff onto the agent's very next inference. The agent doesn't have to call `bash_output()` — completion comes to it. Same shape as the `OpsControlNotificationMiddleware` workload-state pattern (ADR-0006), and same shape as Claude Code's native background-bash auto-notification.

---

## Data Flow: Single Objective

```
Orchestrator reads OPPLAN
        │
        ▼
  Pick next pending objective
        │
        ▼
  Spawn specialist agent (fresh context)
  ┌─────────────────────────────────────────────┐
  │  System prompt: RoE + skills + OPPLAN status │
  │  Tools: bash → sandbox (via Docker socket)   │
  │         read_file / write_file → workspace/  │
  │         kg_* → Neo4j (bolt://neo4j:7687)     │
  │         cve_lookup → NVD / OSV / EPSS APIs   │
  └─────────────────────────────────────────────┘
        │
        ▼
  Agent executes, writes findings to workspace/
        │
        ▼
  Returns PASSED | BLOCKED
        │
        ▼
  Orchestrator updates OPPLAN status
  Findings appended to disk
        │
        ▼
  Next objective
```

---

## Security Boundaries

| Boundary | Enforcement |
|----------|-------------|
| Sandbox → Management services | Separate Docker networks; LiteLLM/PostgreSQL/LangGraph/Web are not routable from `sandbox-net` |
| LangGraph → Sandbox | Docker socket only (no TCP) |
| Sandbox → KGStore Neo4j | Allowed (intentional shared service for cross-domain attack graph writes) |
| Credential isolation | Provider API keys live on `buggy-net`; the sandbox never sees them |
| Host isolation | All commands run inside Docker; no host filesystem access except the engagement-scoped `/workspace` bind mount |
