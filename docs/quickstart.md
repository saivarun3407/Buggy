# Quick Start — run a hunt in one command

The fastest path from zero to a running hunt. If you want the full tour
(providers, OAuth, dashboard), see [Getting Started](getting-started.md).

## 1. Install

**macOS / Linux / WSL2**
```bash
curl -fsSL https://buggy.red/install | bash
```
**Windows (PowerShell)**
```powershell
irm https://buggy.red/install.ps1 | iex
```

## 2. Configure once

```bash
buggy onboard
```
Pick a provider and paste one API key (or a subscription login). That's the
only setup. Config is saved to `~/.buggy/.env`.

> You need Docker + Docker Compose v2 installed and running. Everything else
> runs in containers.

## 3. Hunt

Point it at a target you're authorized to test — one command brings the
whole stack up (first run is ~75s cold) and runs the engagement:

```bash
buggy hunt example.com
```

More targets and wider scope, still one command:

```bash
# Several assets at once
buggy hunt api.example.com app.example.com

# Include subdomains explicitly (scope is never widened for you)
buggy hunt example.com --include-subdomains

# A URL, a custom in-scope pattern, an exclusion, and a focus note
buggy hunt https://example.com \
    --scope "*.example.com" \
    --exclude "admin.example.com" \
    --instruction "focus on auth and access control"

# Write the scope/plan bundle and stop — review before anything runs
buggy hunt example.com --plan-only
```

Scope defaults to **exactly the targets you name** — subdomains and extra
hosts are only added when you ask with `--include-subdomains` / `--scope`.
You are asked once to confirm you are authorized (`--yes` skips the prompt).

### What happens after you press enter

| Stage | What | LLM |
|---|---|---|
| 1. Scope | An enforced scope is written for exactly those hosts: enforce mode, 10 requests/second, approval before any state-changing request, and no network path from the agent's shell to the target | no |
| 2. Recon | The pipeline maps hosts, services, URLs, API specifications and known issues with pinned tools. Progress is shown per stage | no |
| 3. Report | `~/.buggy/control/<engagement>/recon-report.md`: known issues by severity with fixes, live services, APIs, and what to test next | no |
| 4. Agents | The agents read the recon data, choose what to test, run the deterministic probes and chain what they find. Skipped when no model is configured or with `--no-agent` | yes |

Stages 1–3 need no model at all:

```bash
buggy hunt https://example.com --no-agent
```

State-changing requests wait for you:

```bash
docker compose --profile operator run --rm operator buggy-cli approvals list <engagement>
```

```bash
docker compose --profile operator run --rm operator buggy-cli approvals allow <engagement> <request-id>
```

Useful switches: `--rps N` (max 50), `--port-scan`, `--crawl-exclude REGEX`,
`--internal` (target on a private network), `--allow-sandbox-network` (lets the
agent's shell reach the target; requests sent that way are not held for
approval), `--lab` (a training target you own: no approval holds). A scope
pattern `*.example.com` covers one label; `**.example.com` covers any depth.

## 3b. Bug bounty (HackerOne / Bugcrowd)

For platform programs, let the Scout pull the scope straight from the
program so you never hand-type it:

```bash
# Export your platform credentials first
export HACKERONE_API_USERNAME=... HACKERONE_API_TOKEN=...
export BUGCROWD_API_TOKEN=...

buggy bounty                     # both platforms
buggy bounty --platform hackerone
```

It authenticates, lists the programs you can access, lets you pick one,
ingests that program's scope + exclusions + reporting policy into the
enforced RoE, and then hunts — no manual scope entry.

## 4. Review results

Findings and evidence land under:

```
~/.buggy/workspace/<engagement>/
  findings/FIND-*.md        # one file per verified finding
  (scope decisions: ~/.buggy/audit/<engagement>/roe-decisions.jsonl)
```

Open the full terminal UI to watch or resume a run, and the attack-graph
sidebar:

```bash
buggy            # interactive UI + engagement picker
```

Verify the audit ledger anytime:

```bash
buggy-cli audit verify --engagement <engagement>
```

## 5. Stop

```bash
buggy stop       # stop services, keep data
```

---

### Headless / CI

`hunt` and `bounty` are also available without the launcher, against an
already-running stack, via the Python CLI:

```bash
buggy-cli hunt example.com --non-interactive
buggy-cli bounty --print-kickoff        # inspect the Scout kickoff
```

> **Authorization**: only run Buggy against systems you own or have
> explicit written permission to test. See the disclaimer in the README.
