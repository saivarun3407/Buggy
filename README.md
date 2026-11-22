# Buggy — authorized web app and API testing

Give Buggy the URL of a web app or API you are authorized to test. It enforces
a scope for that target, maps it with a deterministic recon pipeline, signs in
as your test accounts, runs probes class by class through an evidence gateway,
re-proves and grades what it finds, records the proof, and writes reports.

## Status of this repository

This repository (`saivarun3407/Buggy`) is a fork that is being turned into an
**authorized bug-bounty testing system for web apps and APIs**. Tools run as
plain code and write structured results; a model is only used to choose what
to test, chain findings and judge results. Last checked 2026-11-21.

| Part | State |
|---|---|
| Scope enforcement, recon pipeline, recon report | Works, no model needed. Run on local practice targets. |
| Automatic read-only probe sweep, re-proof, grading, reports (Markdown, HTML, JSON, SARIF) | Works, no model needed. See [findings](docs/findings.md). |
| Approval before anything state-changing, including one approval per probe run | Works. Approving is always a person's step. |
| Agents (choosing tests, chaining) | Run with a model key (`buggy onboard`), or **with no key through Claude Code** on your machine (`buggy agent <engagement>`; see [Claude Code agent](docs/claude-code-agent.md)). Measured so far: one bounded Claude Code run on the practice apps. |
| Releases and the one-line installer | The workflows publish from this repository, but **no release has been cut yet**. Until the first tag, run from source (below). See [releasing](docs/releasing.md). |
| CI | Lint, type check, the test suite, dependency audit and compose validation pass locally on this branch. |

Run from source until a release exists:

```bash
git clone https://github.com/saivarun3407/Buggy.git
cd Buggy
make build-images        # builds every image the stack starts (slow the first time)
mkdir -p ~/.buggy/workspace ~/.buggy/control ~/.buggy/audit ~/.buggy/secrets ~/.buggy/telemetry
for name in SANDBOX_TOKEN EGRESS_GUARD_TOKEN BUGGY_STACK_MCP_TOKEN BUGGY_AUDIT_HMAC_KEY; do echo "$name=$(openssl rand -hex 24)"; done >> .env
docker compose up -d
docker compose --profile operator run --rm operator buggy-cli doctor --in-container
docker compose --profile operator run --rm operator buggy-cli hunt https://your-target.example --no-agent
```

`--no-agent` stops after recon, the probe sweep and the reports; drop it once
a model is configured.

Only test systems you are authorized to test. Scope is enforced from the
program's own scope data, and state-changing requests wait for your approval.

## How a hunt runs

1. **Scope.** `buggy hunt <url>` enforces a scope of exactly that host (or the
   scope of a bounty program you import). Every request the stack sends is
   checked against it. See [scope enforcement](docs/security/scope-enforcement.md).
2. **Recon.** The deterministic [recon pipeline](docs/pipeline.md) maps the
   target with pinned scanners; no model is involved.
3. **Probes.** Probes run class by class through the
   [evidence gateway](docs/evidence-and-probes.md): scope check, an approval
   hold for any state-changing request, a rate limit, and a signed
   [audit ledger](docs/security/audit-ledger.md) entry for every request.
4. **Findings.** Each candidate is re-proved, graded and stored with its proof;
   reports are written as Markdown, HTML, JSON and SARIF. See
   [findings](docs/findings.md).
5. **Reasoning.** Choosing what to test next and chaining findings is done
   either by Buggy's built-in agents (the LangGraph runtime, with a model key)
   or by Claude Code through the agent bridge
   (`python -m buggy.agent_bridge`, see [Claude Code agent](docs/claude-code-agent.md)).

## Commands

The launcher (`clients/launcher`, Go):

| Command | What it does |
|---|---|
| `buggy hunt <url>` | Scope, recon, probes and reports in one command, then the agents |
| `buggy agent <engagement>` | Run the agent stage with Claude Code (no model key) |
| `buggy demo` | The lite stack against the local practice apps |
| `buggy doctor` | Check the host and the stack |
| `buggy start` / `stop` / `update` / `onboard` | Manage the full stack |

The headless CLI (`buggy-cli`, also inside the operator image): `hunt`,
`doctor`, `status`, `approvals`, `audit`, `scope`, `program`, `retest`,
`ci-gate`, `tools`, and more — see [CLI reference](docs/cli-reference.md) and
[Buggy in CI](docs/ci.md).

## Install

**Prerequisites**: [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2.

Once a release exists:

```bash
curl -fsSL https://raw.githubusercontent.com/saivarun3407/Buggy/main/scripts/install.sh | bash
buggy onboard                     # model provider and key (or skip and use Claude Code)
buggy hunt https://example.com    # scope, recon, probes, reports, then agents
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/saivarun3407/Buggy/main/scripts/install.ps1 | iex
```

→ **[Quick start](docs/quickstart.md)** · **[Full setup walkthrough](docs/setup-guide.md)**

## What the stack runs

| Service | Role |
|---|---|
| `pipeline`, `pipeline-mcp` | Deterministic recon and its read-only MCP server |
| `capture-mcp`, `scope-mcp` | Evidence gateway and scope server |
| `browser-mcp` | Scope-enforced browser for sign-in and client-side checks |
| `egress-guard` | The sandbox's only way out, filtered by scope |
| `operator` (profile) | One-off operator commands (`buggy-cli ...`) |
| `litellm`, `langgraph`, `postgres`, `neo4j`, `skillogy`, `sandbox` | Built-in agent runtime |
| `web`, `cli` (profiles) | Dashboard and terminal client for the built-in agents |

The lite stack (`docker-compose.lite.yml`) runs only the recon pipeline and
the operator image; `docker-compose.lab.yml` adds local practice targets and
`docker-compose.demo.yml` makes those a runnable demo. See
[architecture](docs/architecture.md) and [readiness](docs/readiness.md).

## Agents

The orchestrator (`buggy`) plans and delegates to the agents that test web apps
and APIs: `recon`, `exploit`, `analyst`, and the specialist slate `scout`,
`asvs`, `mitre_attack`, `api_security`, `authn_session`, `business_logic`,
`clientside_security`, `graphql_security`, `llm_security`, `secrets_cicd` and
`ssrf_cloud`. `soundwave` writes the engagement plan for a new engagement.
See [agents](docs/agents.md) and [models](docs/models.md).

## Documentation

| Topic | Doc |
|-------|-----|
| Run a hunt in one command | [Quick Start](docs/quickstart.md) |
| Findings: proof, grading, reports | [Findings](docs/findings.md) |
| Evidence gateway, probes, MCP servers | [Evidence and probes](docs/evidence-and-probes.md) |
| Recon pipeline | [Pipeline](docs/pipeline.md) |
| Running against a bounty program | [Bounty programs](docs/bounty-programs.md) |
| Claude Code as the agent | [Claude Code agent](docs/claude-code-agent.md) |
| CI gate and SARIF | [Buggy in CI](docs/ci.md) |
| Security controls | [Security](docs/security/security-controls.md) |
| All CLI commands | [CLI Reference](docs/cli-reference.md) |
| Releasing | [Releasing](docs/releasing.md) |
| What was removed in the scope cut | [Deletion inventory](docs/deletion-inventory.md) |

## Contributing

```bash
git clone https://github.com/saivarun3407/buggy.git
cd Buggy
make dev      # backend hot-reload (compose watch)
```

→ **[Contributing guide](docs/contributing.md)**

## Disclaimer

Do not use this project on any system or network without explicit written authorization from the system owner. Unauthorized access to computer systems is illegal. You are solely responsible for your actions. The authors and contributors assume no liability for misuse.

## License

[Apache-2.0](LICENSE)
