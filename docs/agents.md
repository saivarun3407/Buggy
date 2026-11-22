# Agents

Buggy's built-in agents test web apps and APIs. The orchestrator (`buggy`)
reads the OPPLAN and delegates to specialist sub-agents; `soundwave` writes the
engagement plan for a new engagement. The same work can instead be done by
Claude Code through the agent bridge (see [Claude Code agent](claude-code-agent.md)).

Every role that sends requests or reads results gets the stack's own tool
servers (`tools/stack_mcp.py`): the recon store, the scope server, the
evidence gateway and the scoped browser.

---

## Agent Roster

### Orchestrator and planner

| Agent | Role |
|-------|------|
| **Buggy** | Orchestrator. Reads the OPPLAN, dispatches objectives to the sub-agents below through `task()`, and tracks status transitions. |
| **Soundwave** | Engagement planner. Standalone graph (not a sub-agent of Buggy). Interviews the operator and writes the engagement bundle (RoE, CONOPS, OPPLAN and the supporting documents) that the orchestrator consumes. |

### Standard sub-agents

| Agent | Role |
|-------|------|
| **Recon** | Reads the deterministic recon store and plans what to probe; does not send probes itself. |
| **Exploit** | Tests a web or API weakness through the evidence gateway and records what it proved. |
| **Analyst** | Source and dependency review, chaining findings, and the proof-gated finding recorder. |

### Web/API specialists (`bounty` bundle)

| Agent | Role |
|-------|------|
| **Scout** | Intake: program selection and the enforced scope. |
| **ASVS** | Maps coverage to OWASP ASVS 5.0 requirements. |
| **MITRE ATT&CK** | Maps observed behaviour to ATT&CK techniques. |
| **API security** | REST/OpenAPI weaknesses (BOLA/BFLA, mass assignment, injection). |
| **AuthN / session** | Sign-in, session, token and account-takeover weaknesses. |
| **Business logic** | Workflow abuse and race conditions. |
| **Client-side** | XSS, DOM issues and other browser-side weaknesses. |
| **GraphQL** | GraphQL schema exposure, authorization and query abuse. |
| **LLM / AI app** | Prompt injection and other weaknesses of LLM features. |
| **Secrets / CI-CD** | Exposed secrets and build-pipeline exposure. |
| **SSRF / cloud metadata** | SSRF and what it reaches. |

---

## Fresh Context Model

Every specialist agent runs with a **clean context window** for each objective:

- The orchestrator picks the next pending objective from the OPPLAN
- A new agent instance is spawned with only what it needs: the objective, RoE guard rails, and relevant findings from disk
- The agent executes, writes findings to `workspace/`, and returns a `PASSED` or `BLOCKED` signal
- The orchestrator updates the OPPLAN and moves to the next objective

This prevents context window bloat and token accumulation across a long engagement.

---

## Middleware Stack

Each agent assembles its middleware stack from a fixed set of named **slots** (`MiddlewareSlot`). The enum declaration order is the canonical assembly order — every factory walks the enum top-to-bottom and instantiates only the slots its role opts into via `SLOTS_PER_ROLE`. Plugins replace or disable slots by name (`PluginBundle.replaced_middleware` / `disabled_middleware`); slot definitions and the per-role mapping live in `buggy_core.contracts.slots`, the langchain-bound factories in `buggy.agents.middleware_slots`.

### Safety stack (every agent)

These slots are part of the base set every role receives — they are the engagement guard rails:

| Middleware | Slot | Purpose |
|------------|------|---------|
| `RoEGuardrailMiddleware` | `roe-guardrail` | Legal/safety gate on tool calls — extracts the target, evaluates it against the Rules of Engagement, and appends to a chained audit log (`<workspace>/audit/roe-decisions.jsonl`, or `BUGGY_ROE_AUDIT_PATH`). A fast-fail command-parse gate; the authoritative scope boundary is the egress layer (sandbox nftables, on by default for `enforce` mode, opt-out via `BUGGY_EGRESS_DISABLE`). The pre-rename name `RoEEnforcementMiddleware` / slot `roe-enforcement` stays as a compat alias until 2.0.0. |
| `UntrustedOutputMiddleware` | `untrusted-output` | Quarantines attacker-influenceable tool output (bash stdout, file reads, KG queries) inside a `<UNTRUSTED_TOOL_OUTPUT>` envelope so hostile content can't re-author the agent's instructions. |
| `PromptInjectionShieldMiddleware` | `prompt-injection-shield` | Deny-list wrap of attacker-controlled tool output (HTTP bodies, banners, file reads); dedups against `UNTRUSTED_OUTPUT` and does not re-inject the system policy. |
| `EventLogMiddleware` | `event-log` | Structured event logging for every model and tool call. |
| `BudgetEnforcementMiddleware` | `budget` | Enforces per-engagement spend caps (no-op when caps ≤ 0). |

Bash-executing agents and the orchestrator additionally get:

| Middleware | Slot | Purpose |
|------------|------|---------|
| `EngagementContextMiddleware` | `engagement-context` | Injects engagement metadata (slug, workspace) and per-challenge state (target URL, tags, flag format, mission brief) into every model call. Carries RoE scope into tool calls — it is **safety-critical**. |
| `SandboxNotificationMiddleware` | `sandbox-notification` | Tracks background-job completion and emits the CLI's `Background command` event. Bash agents only. |
| `HITLApprovalMiddleware` | `hitl-approval` | Operator-approval gate for high-impact actions (credential dumping, destructive ops). **Opt-in** — skipped unless `BUGGY_HITL__ENABLED` is set to a truthy value (off by default so engagements don't freeze waiting on a human). |

### Framework middleware

| Middleware | Slot | Purpose |
|------------|------|---------|
| `SkillsMiddleware` | `skills` | Loads `SKILL.md` frontmatter, filters by agent role, and injects matching skill descriptions into the system prompt. Full skill content is fetched on demand via the `load_skill` tool — `read_file` / `bash cat` **do not** resolve `/skills/*` (that tree is served in-process by a local `FilesystemBackend`, not the sandbox). |
| `FilesystemMiddleware` | `filesystem` | Provides `read_file`, `write_file`, `edit_file`, `ls`, `glob`, `grep` tools backed by the sandbox filesystem. Execute is intentionally stripped — agents use the dedicated `bash` tool for command execution. |
| `SubAgentMiddleware` | `subagent` | Allows the orchestrator (Buggy) to delegate objectives to specialist sub-agents via the `task()` tool. |
| `OPPLANMiddleware` | `opplan` | Injects the current OPPLAN progress table into every LLM call and provides CRUD tools for objective management. |
| `ModelOverrideMiddleware` | `model-override` | Per-objective model selection. Orchestrator only. |
| `ModelFallbackMiddleware` | `model-fallback` | Switches to a fallback model on provider outage, rate limit, or context overflow. Conditional — skipped when no fallback chain is configured. |
| `SummarizationMiddleware` | `summarization` | Auto-compacts conversation history when the context window approaches capacity. |
| `AnthropicPromptCachingMiddleware` | `prompt-caching` | Caches static system prompt content for Anthropic models to reduce token costs. Silently no-ops on non-Anthropic providers. |
| `PatchToolCallsMiddleware` | `patch-tool-calls` | Sanitizes and normalizes tool call formats for compatibility across model providers (e.g. repairs dangling tool calls). |

### Safety-critical slots

`SAFETY_CRITICAL_SLOTS` — `engagement-context`, `roe-guardrail`, `untrusted-output`, `prompt-injection-shield`, `sandbox-notification`, `hitl-approval` — can only be replaced or disabled by a plugin when `BUGGY_ALLOW_SAFETY_OVERRIDES=1` is set in the environment. The gate is enforced by `build_middleware` in `buggy.agents.build`; without it, an override raises `SafetyOverrideViolation`. Replacement is fine if the new middleware honours the same contract — the gate exists so an accidentally-installed plugin can't silently subvert the safety story.

### Stack per Agent Role

Each diagram lists the slots a role instantiates, in `MiddlewareSlot` enum order (the order they wrap each call). `HITLApproval` appears in the bash-agent and orchestrator stacks but is opt-in — skipped at runtime unless `BUGGY_HITL__ENABLED` is truthy.

**Buggy (Orchestrator)** — full stack with engagement context, sub-agent dispatch, and per-objective model override. No `SandboxNotification`.

```
EngagementContext → RoEEnforcement → HITLApproval → UntrustedOutput → PromptInjectionShield
                  → Skills → Filesystem → SubAgent → OPPLAN → EventLog → Budget → ModelOverride
                  → ModelFallback → Summarization → AnthropicPromptCaching → PatchToolCalls
```

**Bash-executing specialists** (Recon, Exploit, Analyst and the web/API specialists) — the full bash-agent stack including `EngagementContext` and `SandboxNotification`.

```
EngagementContext → RoEEnforcement → HITLApproval → UntrustedOutput → PromptInjectionShield
                  → Skills → Filesystem → EventLog → SandboxNotification → Budget
                  → ModelFallback → Summarization → AnthropicPromptCaching → PatchToolCalls
```

These specialists also have the `bash` tool for command execution inside the sandbox; `FilesystemMiddleware` covers all file I/O.

**Soundwave (Planner)** — base set + `EngagementContext`. No `bash`, no sub-agents, no `SandboxNotification`, no `HITLApproval` (document generation only).

```
EngagementContext → RoEEnforcement → UntrustedOutput → PromptInjectionShield → Skills → Filesystem
                  → EventLog → Budget → ModelFallback → Summarization → AnthropicPromptCaching → PatchToolCalls
```
