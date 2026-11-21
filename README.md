[![English](https://img.shields.io/badge/Language-English-blue?style=for-the-badge)](README.md)
[![한국어](https://img.shields.io/badge/Language-한국어-red?style=for-the-badge)](README_KO.md)

<div align="center">
  <img src="assets/logo_banner.png" alt="Buggy Logo">
</div>

<h1 align="center">Buggy — Autonomous Red Team Agent</h1>

<p align="center"><i>"Another AI hacker? Let us guess — it runs nmap and writes a report."</i></p>

<div align="center">

<a href="https://github.com/saivarun3407/buggy/blob/main/LICENSE">
  <img src="https://img.shields.io/github/license/PurpleAILAB/Buggy?style=for-the-badge&color=blue" alt="License: Apache 2.0">
</a>
<a href="https://github.com/saivarun3407/buggy/stargazers">
  <img src="https://img.shields.io/github/stars/PurpleAILAB/Buggy?style=for-the-badge&color=yellow" alt="Stargazers">
</a>
<a href="https://github.com/saivarun3407/buggy/graphs/contributors">
  <img src="https://img.shields.io/github/contributors/PurpleAILAB/Buggy?style=for-the-badge&color=orange" alt="Contributors">
</a>

<br/>

<a href="https://discord.gg/TZUYsZgrRG">
  <img src="https://img.shields.io/badge/Discord-Join%20Us-7289DA?logo=discord&logoColor=white&style=for-the-badge" alt="Join us on Discord">
</a>
<a href="https://buggy.red">
  <img src="https://img.shields.io/badge/Website-buggy.red-brightgreen?logo=vercel&logoColor=white&style=for-the-badge" alt="Website">
</a>
<a href="https://docs.buggy.red">
  <img src="https://img.shields.io/badge/Docs-docs.buggy.red-8B5CF6?logo=bookstack&logoColor=white&style=for-the-badge" alt="Documentation">
</a>
<a href="https://app.buggy.red">
  <img src="https://img.shields.io/badge/Live%20App-app.buggy.red-FF2D55?logo=rocket&logoColor=white&style=for-the-badge" alt="Live hosted app">
</a>

</div>

<br/>

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
| Agents (choosing tests, chaining) | Need a model key (`buggy onboard`). **No agent run has been measured here yet.** |
| Releases and the one-line installer | The workflows publish from this repository, but **no release has been cut yet**. Until the first tag, run from source (below). See [releasing](docs/releasing.md). |
| CI | Lint, type check, 10,900+ tests, dependency audit and compose validation pass locally on this branch. |

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

The hosted app, website, Discord, sponsor link and PyPI packages named further
down belong to the upstream project this fork came from, not to this
repository.

Only test systems you are authorized to test. Scope is enforced from the
program's own scope data, and state-changing requests wait for your approval.

---

<div align="center">
  <video src="https://github.com/user-attachments/assets/b3fd40d8-e859-4a39-97f4-bd825694ad96" width="800" controls></video>
</div>


<div align="center">

### ☁️ Don't want to self-host? **Buggy is live in the cloud.**

Skip the Docker setup — run autonomous red-team engagements right from your browser.

<a href="https://app.buggy.red">
  <img src="https://img.shields.io/badge/Launch%20the%20Live%20App-app.buggy.red-FF2D55?logo=rocket&logoColor=white&style=for-the-badge" alt="Launch the live app at app.buggy.red">
</a>

</div>

<div align="center">
  <video src="https://github.com/user-attachments/assets/2344d6f7-fa44-42bb-9492-1c203e56df3c" width="800" controls></video>
</div>

---

## Install

**Prerequisites**: [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2.
Supported on macOS (Apple Silicon + Intel), Linux (amd64 + arm64), and Windows (amd64 + arm64) — native via PowerShell or via WSL2 (Ubuntu / Kali).

**macOS / Linux / WSL2**
```bash
curl -fsSL https://raw.githubusercontent.com/saivarun3407/Buggy/main/scripts/install.sh | bash
buggy onboard   # Interactive setup wizard (provider, API key, model profile)
buggy hunt https://example.com   # One command: scope, recon, report, then agents
buggy bounty             # Pick a HackerOne/Bugcrowd program and hunt it
buggy           # Or open the full interactive terminal CLI
```

`buggy hunt <url>` enforces a scope of exactly that host, maps it with the deterministic recon pipeline (no LLM), writes a recon report, then lets the agents choose what to test. State-changing requests wait for your approval. See [Quick Start](docs/quickstart.md).

The default start brings up the core management plane (LiteLLM, PostgreSQL, Neo4j, Skillogy, LangGraph, sandbox) and launches the terminal CLI. Specialist workloads (BloodHound CE, Sliver C2, Ghidra MCP, …) and the web dashboard come up on demand — the orchestrator spawns specialists via `ops_start("ad")` etc., and you bring up the dashboard from inside the CLI with `/web` (see [Web Dashboard](docs/web-dashboard.md)).

**Windows (PowerShell, native)**
```powershell
irm https://raw.githubusercontent.com/saivarun3407/Buggy/main/scripts/install.ps1 | iex
buggy onboard
buggy
```

→ **[Quick start](docs/getting-started.md)** · **[Full setup walkthrough](docs/setup-guide.md)**

### Use as a library (pip)

Building on top of the agents — a product, a research integration, or a custom orchestrator? Install the SDK from PyPI:

```bash
pip install buggy              # core SDK
pip install "buggy[neo4j]"     # + the knowledge-graph attack-chain tools
```

`buggy` is a **client SDK**: it ships the agent factories, middleware, tools, and skills, and routes LLM calls and sandbox execution to runtime services over HTTP (`BUGGY_LLM__PROXY_URL`, `SANDBOX_URL`). Running agents still needs those services — use the Docker stack above, or point the URLs at your own equivalents. See **[Buggy as a library](docs/library-usage.md)** for the factory override surface, declarative `PluginBundle` plugins, and the safety gate.

---

## 💖 Support Buggy

[![Sponsor](https://img.shields.io/badge/Sponsor-Buggy-red?style=for-the-badge&logo=github)](https://github.com/sponsors/PurpleCHOIms)

We're building Buggy toward an **Offensive Vaccine** for the AI-driven threat landscape. If you believe in autonomous red teaming as a path to stronger defense, consider supporting the project.

---

## Benchmark

> **Integrity status: no current validated XBOW score.** The historical
> `102 / 104` claim was invalidated after review found that the old evaluator
> derived each expected flag from the public challenge ID. The provider now
> generates an unpredictable flag for every setup and fails closed when setup
> provenance is missing. A fresh full-suite run with retained traces is pending.

- **[Historical artifacts and invalidation details](benchmark/results/README.md)**
- **[Cross-project comparison and evidence caveats](docs/benchmark-comparison.md)**
- **[Engineering review that identified the issue](docs/research/buggy-review-2026-11-17.md)**

---

## What is Buggy?

The "AI + hacking" space is full of demos that run nmap and print a report. That's not what this is.

**Buggy is a professional autonomous Red Team agent.** It executes realistic attack chains — reconnaissance, exploitation, privilege escalation, lateral movement, C2 — the way a real adversary would, not the way a scanner does.

But more importantly: it operates under the discipline that separates red teamers from script kiddies. Before a single packet leaves the wire, Buggy generates a complete engagement package — **RoE**, **ConOps**, **Deconfliction Plan**, and **OPPLAN** with MITRE ATT&CK mapping — and every action runs inside those defined rules.

→ **[Engagement workflow deep dive](docs/engagement-workflow.md)**

---

## Why Buggy?

**Real kill chains, not checkbox scans.** Buggy reads an OPPLAN and pursues objectives through whatever path opens up — pivoting, adapting, chaining techniques.

**Interactive shells, actually.** Real offensive tools are interactive (`msfconsole`, `sliver-client`, `evil-winrm`). Buggy runs every command inside persistent tmux sessions with automatic prompt detection — so when a tool drops into an interactive prompt, the agent sends follow-up commands without workarounds.

**Hardened sandbox isolation.** All commands run inside a Kali Linux sandbox on a dedicated operational network (`sandbox-net`), separate from the management plane (`buggy-net`). LangGraph drives the sandbox via the Docker socket. → **[Architecture](docs/architecture.md)**

**Offense serves defense.** The planned [Offensive Vaccine](docs/offensive-vaccine.md) loop will turn findings into defense improvements through an attack → defend → verify cycle.

---

## Architecture

<div align="center">
  <img src="assets/buggy_infra.svg" alt="Buggy Infrastructure" width="680">
</div>

Two-network design. The **always-on** management plane (LiteLLM, PostgreSQL, Skillogy, LangGraph) and the always-on sandbox plane stay up across the whole engagement; everything else is **dynamic-spawn** — the Web dashboard comes up on `/web` from the CLI, and specialist workloads (BloodHound CE, Sliver C2, Ghidra MCP, …) come up only when the orchestrator calls `ops_start(...)` (see [ADR-0006](docs/adr/0006-agent-driven-container-lifecycle.md)). Networks: management on `buggy-net`; sandbox + C2 server + targets on `sandbox-net`. Neo4j is dual-homed so the agent (on management) can persist findings written from inside the sandbox.

→ **[Architecture deep dive](docs/architecture.md)** · **[Knowledge graph](docs/knowledge-graph.md)**

---

## Agents

16 specialist agents organized by kill chain phase, with a fresh context window per objective — no accumulated noise.

Orchestration · Reconnaissance · Exploitation · Post-Exploitation · Vulnerability Research · Domain Specialists (AD, Cloud, Smart Contracts, Reversing, Analyst).

→ **[Full agent roster and middleware stack](docs/agents.md)**

---

## Models & Providers

Tier-based, credentials-aware fallback chain. You declare which credentials you have in priority order; Buggy builds the primary→fallback chain at every tier from there.

| Profile | Tier per agent | Use case |
|---------|----------------|----------|
| **eco** (default) | Per-agent (HIGH for orchestrator/exploiter/patcher/analyst, MID for execution, LOW for recon/soundwave) | Production |
| **max** | Every agent on HIGH | High-value targets |
| **test** | Every agent on LOW | Development / CI |

**Tier-mapped providers**: Anthropic, OpenAI, Google Gemini, MiniMax, DeepSeek, xAI, Mistral, OpenRouter, Nvidia NIM, Ollama (local).
**Subscription OAuth**: Claude Max/Pro/Team, ChatGPT Pro/Plus/Team, Gemini Advanced, Copilot Pro, SuperGrok, Perplexity Pro.

Configure via `buggy onboard`. → **[Full model reference & fallback examples](docs/models.md)**

---

## Documentation

| Topic | Doc |
|-------|-----|
| Run a hunt in one command (fastest path) | [Quick Start](docs/quickstart.md) |
| Installation and first engagement | [Getting Started](docs/getting-started.md) |
| Complete setup, OAuth, providers, dashboard | [Setup Guide](docs/setup-guide.md) |
| All CLI commands and keyboard shortcuts | [CLI Reference](docs/cli-reference.md) |
| All `make` targets | [Makefile Reference](docs/makefile-reference.md) |
| Agent roster and middleware | [Agents](docs/agents.md) |
| Model profiles and fallback chain | [Models](docs/models.md) |
| Skill system and format spec | [Skills](docs/skills.md) |
| Web dashboard features and setup | [Web Dashboard](docs/web-dashboard.md) |
| System architecture and network isolation | [Architecture](docs/architecture.md) |
| Neo4j knowledge graph | [Knowledge Graph](docs/knowledge-graph.md) |
| End-to-end engagement workflow | [Engagement Workflow](docs/engagement-workflow.md) |
| Offensive Vaccine loop | [Offensive Vaccine](docs/offensive-vaccine.md) |
| Contributing to Buggy | [Contributing](docs/contributing.md) |

---

## Contributing

```bash
git clone https://github.com/saivarun3407/buggy.git
cd Buggy
make dogfood  # Full OSS UX (launcher → onboard → CLI) on local code
make dev      # Backend hot-reload (compose watch) — daily dev loop
```

→ **[Contributing guide](docs/contributing.md)**

---

## Community

Join the [Discord](https://discord.gg/TZUYsZgrRG) — ask questions, share engagement logs, discuss techniques.

---

## Disclaimer

Do not use this project on any system or network without explicit written authorization from the system owner. Unauthorized access to computer systems is illegal. You are solely responsible for your actions. The authors and contributors assume no liability for misuse.

---

## License

[Apache-2.0](LICENSE)

---

<div align="center">
  <img src="assets/main.png" alt="Buggy">
</div>
