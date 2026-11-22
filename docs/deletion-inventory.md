# Deletion inventory (cards K1, K2, K3)

The product has one goal: the operator gives the URL of a web app or API they
are authorized to test; Buggy enforces a scope for it, maps it with the
deterministic recon pipeline, signs in as test accounts, runs deterministic
probes class by class through the evidence gateway (scope check, approval hold
for state-changing requests, rate limit, audit ledger), re-proves and grades
findings, records proof and writes reports. Reasoning that needs a model is
done by Buggy's built-in agents (LangGraph runtime with a model key) or by
Claude Code through the agent bridge (`python -m buggy.agent_bridge`).

This file lists every top-level area, whether that goal uses it, the evidence,
and what was done. The evidence is the import graph (who imports the module
outside itself and its tests, from
`grep -rn "from buggy.<module>\|import buggy.<module>"`), the compose files,
the Dockerfiles and the release workflows; names were not used as evidence.

Legend for **Goal uses it**:

- **YES**: on the URL-to-report path, or a gate that guards it.
- **NO**: nothing on that path imports, starts or reads it.
- **RUNTIME-ONLY**: only the built-in agent runtime uses it. The runtime as such
  (LiteLLM, the LangGraph server, Postgres, Neo4j, Skillogy, the sandbox, the
  web dashboard, the Go launcher, the web/API testing agents and their
  middleware) is waiting on the owner's decision (card K4) and is not deleted
  here.

Legend for **Action**: KEEP, DELETE (done in this pass, see "Deleted" below),
DECIDE-K4 (left for the K4 decision).

## Python package `packages/buggy/buggy`

Importer counts are files outside the module that import it; "(n test)" counts
test files among them.

| Area | What it is for | Goal uses it | Evidence | Action |
|---|---|---|---|---|
| `agent_bridge.py` | Claude Code drives the agent stage over MCP | YES | entry point `python -m buggy.agent_bridge`; imports `cli.hunt`, `tools.stack_mcp`, `middleware.loop_guard` | KEEP |
| `capture/` | evidence gateway, scope server, probes, authz matrix | YES | imported by `cli/hunt.py`, `cli/retest.py`, `findings/*`, `scoped_browser/session.py`; compose `capture-mcp`, `scope-mcp` | KEEP |
| `findings/` | candidate → proven → graded finding, retest, report | YES | imported by `cli/hunt.py`, `cli/retest.py`, `cli/ci_gate.py`, `capture/workbench.py`, `program/brief.py` | KEEP |
| `pipeline/` | deterministic recon pipeline and its MCP server | YES | imported by `cli/hunt.py`, `cli/status.py`, `capture/*`, `tools/stack_mcp.py`, `benchmark/lab/lab.py`; compose `pipeline`, `pipeline-mcp` | KEEP |
| `scoped_browser/` | scope-enforced browser for sign-in and client-side probes | YES | compose `browser-mcp`; `tools/stack_mcp.py` browser server | KEEP |
| `egress_guard/` | network egress guard for the sandbox and gateway | YES | imported by `capture/gateway.py`, `scoped_browser/session.py`; compose `egress-guard` | KEEP |
| `memory/` | lessons store read by the workbench | YES | imported by `capture/workbench.py` | KEEP |
| `coordination/` | board/coordination state for the workbench | YES | imported by `capture/workbench.py` | KEEP |
| `program/` | bounty program scope import and brief | YES | imported by `cli/program.py`, `cli/scope.py`, `cli/status.py`, `middleware/roe.py`, `capture/workbench.py` | KEEP |
| `cli/` | `buggy-cli` subcommands (hunt, doctor, status, approvals, audit, scope, program, retest, ci-gate, tools, …) | YES | `buggy-cli` script; launcher `buggy hunt`; `agent_bridge.py`, `benchmark/lab/agent.py` | KEEP |
| `notify.py` | operator notifications for approval holds | YES | imported by `capture/mcp_server.py` | KEEP |
| `readiness.py` | which tools/domains this stack can run (`buggy-cli tools`) | YES | imported by `cli/tools.py`; `docs/readiness.md` | KEEP (deleted domains removed from its table) |
| `skill_audit/` | SKILL.md schema gate (`make audit-skills-strict`) | YES (gate) | `skillogy/builder/skills.py`, `skillogy/server/neo4j_backend.py`; Makefile | KEEP |
| `sandbox_kernel/` | command runner, egress applier, defensive workflows | YES | `cli/assessment.py`, `cli/workflows.py`, `tools/bash/bash.py`, `sandbox_server/app.py`, `middleware/egress.py` | KEEP |
| `assessment_import.py`, `context_export.py` | web/API inventory import/export for `buggy-cli assessment` | YES | `cli/assessment.py`, `tools/assessment.py` | KEEP |
| `telemetry/`, `telemetry_run.py` | local event sink (phone-home is a hard no-op) | YES | `cli/telemetry.py`, `middleware/event_logging.py`, `middleware/loop_guard.py` | KEEP |
| `agents/` | agent factories, prompts, slot wiring | RUNTIME-ONLY | per role below | DECIDE-K4 for the runtime; non-web roles DELETE |
| `middleware/` | agent middleware (RoE, HITL, egress, injection shield, KG, …) | RUNTIME-ONLY | imported by every agent factory and `agents/build.py` | KEEP the web/API pieces (DO NOT DELETE list); `opscontrol_notifications.py` DELETE |
| `backends/` | sandbox filesystem/HTTP backends for agents | RUNTIME-ONLY | 37 non-test importers, all agent factories and `tools/bash` | DECIDE-K4 |
| `llm/` | LLM factory, router, fallback | RUNTIME-ONLY | 32 non-test importers, agent factories and `middleware/model_override.py` | DECIDE-K4 |
| `core/` | subagent streaming, schemas | RUNTIME-ONLY | `agents/standard/buggy.py`, `agents/plugins/vulnresearch.py` | DECIDE-K4 |
| `graph_registry.py`, `server/` | LangGraph graph catalogue and HTTP app | RUNTIME-ONLY | `langgraph.json` `http.app`; launcher `cmd/agent.go` | DECIDE-K4 |
| `runtime/` | event log, recording, shutdown hooks | RUNTIME-ONLY | `cli/export_transcript.py`, `middleware/event_logging.py`, `middleware/kg_internal/store.py` | DECIDE-K4 |
| `reconciliation/` | SAST intake into the KG | RUNTIME-ONLY | `agents/standard/exploit.py`, `middleware/kg_internal/ingest.py` | DECIDE-K4 |
| `skillogy/` | skill graph builder and server | RUNTIME-ONLY | `middleware/skillogy.py`; compose `skillogy`; Makefile skill-graph gates | KEEP (DO NOT DELETE list) |
| `sandbox_server/` | the sandbox's HTTP daemon | RUNTIME-ONLY | `containers/sandbox.Dockerfile` entrypoint `python -m buggy.sandbox_server` | DECIDE-K4 |
| `sandbox_web/` | open-web search engine run inside the sandbox | RUNTIME-ONLY | `tools/web/search.py`, `containers/sandbox.Dockerfile` | DECIDE-K4 |
| `mcp_server/` | `buggy-mcp`: lets external MCP clients drive LangGraph engagements | RUNTIME-ONLY | `buggy-mcp` script only; no importer outside tests; drives the LangGraph API | DECIDE-K4 |
| `skills/` | SKILL.md knowledge loaded by agents | RUNTIME-ONLY | per domain below | per domain |
| `blue_cell/` | purple-team detection tap for the Blue Cell agent | NO | only `tools/defense/blue_cell.py` (Blue Cell role) | DELETE |
| `compat/` (with `plugin_loader.py`, `core/schemas.py` and the other re-export shims) | compat shims for the core/framework split | NO | `buggy/__init__.py` calls `compat` to print a warning; the shims are pinned by `packages/buggy-sdk/tests/test_compat_shim_identity.py` | DECIDE-K4 (see "Not deleted, needs a decision") |
| `tools/` | agent tools | mixed | per subpackage below | per subpackage |

### `packages/buggy/buggy/tools`

| Area | What it is for | Goal uses it | Evidence | Action |
|---|---|---|---|---|
| `stack_mcp.py` | agents' client for the recon/scope/capture/browser MCP servers | YES | `agent_bridge.py`, `agents/build.py`, tools/{browser,proxy,reporting,web} | KEEP |
| `bash/`, `discovery.py`, `filesystem.py`, `skills.py`, `skills_registry.py`, `opplan.py`, `coordinator.py`, `interaction/`, `session/` | agent runtime tools | RUNTIME-ONLY | kept roles (`buggy`, `recon`, `exploit`, `analyst`, bounty `_common.py`) and middleware | DECIDE-K4 |
| `web/`, `browser/`, `proxy/`, `reporting/`, `references/`, `assessment.py`, `evidence/` | web/API testing, reporting, references | RUNTIME-ONLY | bounty `_common.py`, `analyst`, `recon`, `exploit`, `tools/reporting/proof_gate.py` | DECIDE-K4 |
| `research/` | grab-bag of research tools (CVE, chain, SAST, fuzz, bounty scope, CART, …) | RUNTIME-ONLY | 40 non-test importers incl. bounty roles, `cli/scan.py`, `program/importer.py` | DECIDE-K4 (only the parts serving deleted roles removed; see "Not deleted, needs a decision") |
| `ad/` | Active Directory: BloodHound CE client, Kerberos, ADCS | NO | `tools/__init__.py` re-export and `ad_operator` only | DELETE |
| `cloud/` | cloud account enumeration | NO | `tools/__init__.py` and `cloud_hunter` only | DELETE |
| `contracts/` | smart-contract analysis (Slither, …) | NO | `tools/__init__.py`, `contract_auditor`, `tools/research/tools.py` re-export | DELETE |
| `reversing/` | Ghidra / binary reversing | NO | `tools/__init__.py`, `reverser`, `tools/research/tools.py` re-export | DELETE |
| `defense/` | Blue Cell, SIEM/EDR connectors, Offensive Vaccine, CONOPS brief | NO | `blue_cell` role; `buggy` orchestrator carries `VACCINE_TOOLS` (detection-rule generation for a blue team, not on the goal path) | DELETE |
| `ops/` | `ops_start/ops_stop` client for the opscontrol daemon | NO | orchestrator only; every workload in the daemon allowlist (ad, c2, reversing, phishing, mobile, wireless, cloud, iot, ics, forensics, supply-chain) is deleted | DELETE |
| `devin/` | delegate subtasks to the Devin CLI | RUNTIME-ONLY | orchestrator only, gated on `BUGGY_AUTH_DEVIN`; wired into `llm/factory.py` (agent-subscription inventory), `buggy_core/subscriptions.py` and `buggy-cli auth` | DECIDE-K4 |
| `network/` | network protocol scanners | NO | zero importers anywhere | DELETE |
| `mcp/` | client for external MCP tool servers (Kali MCP, HexStrike) | NO | zero non-test importers; nothing calls `load_mcp_tools` | DELETE |

### Agent roles

`tools/stack_mcp.py` gives the web/API tool servers to `_READERS` =
{buggy, recon, analyst, scout, asvs, mitre_attack} and `_TESTERS` = {exploit,
api_security, authn_session, business_logic, clientside_security,
graphql_security, llm_security, secrets_cicd, ssrf_cloud}. Every other role gets
no recon/scope/capture/browser server, so it cannot work through the evidence
gateway.

| Role | What it is | Goal uses it | Evidence | Action |
|---|---|---|---|---|
| `buggy` | orchestrator | RUNTIME-ONLY | `_READERS`; `langgraph.json` | KEEP (K4) |
| `recon`, `analyst` | recon planning, analysis | RUNTIME-ONLY | `_READERS` | KEEP (K4) |
| `exploit` | web exploitation | RUNTIME-ONLY | `_TESTERS` | KEEP (K4) |
| bounty `scout`, `asvs`, `mitre_attack` | intake, ASVS mapping, ATT&CK mapping | RUNTIME-ONLY | `_READERS` | KEEP (K4) |
| bounty `api_security`, `authn_session`, `business_logic`, `clientside_security`, `graphql_security`, `llm_security`, `secrets_cicd`, `ssrf_cloud` | web/API class testers | RUNTIME-ONLY | `_TESTERS` | KEEP (K4) |
| `soundwave` | planning agent that writes RoE/CONOPS before an engagement | RUNTIME-ONLY | launcher `internal/engagement/picker.go`, web dashboard `lib/agents.ts`, `clients/cli` pick it for fresh engagements | DECIDE-K4 (removing it is a launcher/dashboard redesign) |
| `asvs_assessor` | standard-bundle ASVS auditor | NO | not in `_READERS`/`_TESTERS`; duplicate of bounty `asvs` which is | DELETE |
| `ad_operator` | Active Directory | NO | not in the lists | DELETE |
| `reverser` | binary reversing | NO | not in the lists | DELETE |
| `cloud_hunter` | cloud accounts | NO | not in the lists | DELETE |
| `contract_auditor` | smart contracts | NO | not in the lists | DELETE |
| `postexploit` | post-exploitation, lateral movement, privesc | NO | not in the lists | DELETE |
| `phisher` | phishing / social engineering | NO | not in the lists | DELETE |
| `mobile_operator` | mobile apps | NO | not in the lists | DELETE |
| `wireless_operator` | Wi-Fi / RF | NO | not in the lists | DELETE |
| `iot_operator`, `ics_operator` | IoT, ICS/OT | NO | not in the lists | DELETE |
| `osint_operator` | OSINT | NO | not in the lists | DELETE |
| `forensicator` | DFIR | NO | not in the lists | DELETE |
| `supply_chain_operator` | supply chain | NO | not in the lists | DELETE |
| `blue_cell` | purple-team detection validation | NO | not in the lists | DELETE |
| `retrospective` | post-engagement self-review | NO | not registered as a subagent entry point and has no graph, so the orchestrator prompt's `task("retrospective")` call never reaches it | DELETE |
| plugins `vulnresearch`, `scanner`, `detector`, `verifier`, `patcher`, `exploiter` | source-code vuln-research pipeline | NO | not in the lists; separate main agent | DELETE |

### Skill domains (`packages/buggy/buggy/skills`, files)

Standard roles load `/skills/standard/<role-dir>/` plus all of `/skills/shared/`;
bounty roles load `/skills/bounty/<role>/` plus `/skills/shared/`; plugin roles
load `/skills/plugins/<role>/`.

| Domain | Files | Loaded by | Goal uses it | Action |
|---|---|---|---|---|
| `standard/recon` | 21 | recon | RUNTIME-ONLY | KEEP |
| `standard/exploit` | 68 | exploit | RUNTIME-ONLY | KEEP |
| `standard/analyst` | 34 | analyst | RUNTIME-ONLY | KEEP |
| `standard/buggy-orchestrator` | 7 | buggy | RUNTIME-ONLY | KEEP |
| `standard/soundwave` | 25 | soundwave | RUNTIME-ONLY | DECIDE-K4 |
| `bounty/*` (12 dirs) | 12 | bounty roles | RUNTIME-ONLY | KEEP |
| `shared/finding-protocol`, `shared/references`, `shared/opsec`, `shared/defensive-assessment` | 1, 1, 1, 8 | every role | RUNTIME-ONLY | KEEP |
| `benchmark` | 1 | `BENCHMARK_MODE` (CTF conventions) | RUNTIME-ONLY | DECIDE-K4: `BENCHMARK_MODE` also changes `middleware/roe.py`, `middleware/engagement.py` and the KG tools |
| `standard/ad` | 12 | ad_operator | NO | DELETE |
| `standard/reverser` | 25 | reverser | NO | DELETE |
| `standard/cloud` | 20 | cloud_hunter | NO | DELETE |
| `standard/contracts` | 10 | contract_auditor | NO | DELETE |
| `standard/post-exploit` | 16 | postexploit | NO | DELETE |
| `standard/phisher` | 11 | phisher | NO | DELETE |
| `standard/mobile` | 5 | mobile_operator | NO | DELETE |
| `standard/wireless` | 8 | wireless_operator | NO | DELETE |
| `standard/iot`, `standard/ics` | 12, 1 | iot/ics operators | NO | DELETE |
| `standard/osint` | 1 | osint_operator | NO | DELETE |
| `standard/dfir` | 1 | forensicator | NO | DELETE |
| `standard/supply-chain` | 1 | supply_chain_operator | NO | DELETE |
| `shared/adversary-emulation` | 25 | all roles via `/skills/shared/`; written for Blue Cell / APT emulation | NO | DELETE |
| `shared/defense-evasion` | 3 | all roles; EDR/AMSI bypass for endpoints | NO | DELETE |
| `shared/stealth-infra` | 1 | all roles; anti-bot, WAF evasion, password-manager looting | NO | DELETE |
| `plugins/*` (7 dirs) | 24 | vulnresearch family | NO | DELETE |

## Compose services and profiles

| Service (file, profile) | What it is for | Goal uses it | Action |
|---|---|---|---|
| `pipeline`, `pipeline-mcp` (base, lite) | recon pipeline and its MCP server | YES | KEEP |
| `capture-mcp`, `scope-mcp` (base) | evidence gateway, scope server | YES | KEEP |
| `browser-mcp` (base) | scoped browser | YES | KEEP |
| `egress-guard` (base, e2e, lab) | sandbox/gateway egress guard | YES | KEEP |
| `operator` (base, lite; profile `operator`) | operator console image | YES | KEEP |
| lab: `juice-shop`, `dvga`, `dvwa`; demo overlay | `buggy demo` and `benchmark/lab` targets | YES | KEEP |
| `litellm`, `postgres`, `neo4j`, `langgraph`, `skillogy`, `sandbox` (base) | built-in agent runtime | RUNTIME-ONLY | KEEP (K4) |
| `web` (profile `web`), `cli` (profile `cli`) | dashboard, TS terminal client | RUNTIME-ONLY | KEEP (K4) |
| dev / watch / tun / e2e overlays | runtime dev loops and sandbox e2e | RUNTIME-ONLY | KEEP (K4) |
| `ghidra-mcp` (profile `reversing`) | Ghidra bridge for the reverser | NO | DELETE |
| `c2-sliver` (profile `c2-sliver`), volume `sliver_data` | Sliver C2 server | NO | DELETE |
| `bhce`, `bhce-neo4j`, `bhce-postgres-init` (profile `ad`), volumes `bhce_neo4j_*` | BloodHound CE for ad_operator | NO | DELETE |
| `solver` (no profile, always started) | egress-blocked container for Devin benchmark sessions | NO | DELETE (serves only the XBOW/Devin harness) |

## Container images (`containers/`)

| Image | Goal uses it | Action |
|---|---|---|
| `buggy-pipeline` (`pipeline.Dockerfile`) | YES | KEEP |
| `buggy-browser` (`browser.Dockerfile`) | YES | KEEP |
| `buggy-egress-guard` (`egress-guard.Dockerfile`) | YES | KEEP |
| `buggy-litellm`, `buggy-langgraph`, `buggy-sandbox`, `buggy-skillogy`, `buggy-web`, `buggy-cli` | RUNTIME-ONLY | KEEP (K4) |
| `sandbox-e2e.Dockerfile` | RUNTIME-ONLY | KEEP (K4) |
| `buggy-sandbox-reversing` (sandbox.Dockerfile `INSTALL_REVERSING`) | NO | DELETE |
| `buggy-c2-sliver` (`c2-sliver.Dockerfile`, entrypoint) | NO | DELETE |
| `buggy-solver` (`solver.Dockerfile`, entrypoint) | NO | DELETE |

## Clients (`clients/`)

| Client | What it is | Goal uses it | Action |
|---|---|---|---|
| `launcher` (Go) | `buggy hunt/agent/doctor/demo/start/stop/update/onboard` | YES | KEEP; opscontrol daemon code DELETE (no workloads left) |
| `web` | dashboard | RUNTIME-ONLY | KEEP (K4); deleted roles removed from its role table |
| `cli` (TypeScript/Ink) | terminal client for the LangGraph agents | RUNTIME-ONLY | DECIDE-K4 |
| `shared` | streaming helpers shared by `web` and `cli` | RUNTIME-ONLY | DECIDE-K4 |
| `desktop` | Electron wrapper | NO | DELETE (only a CI syntax-check job touches it; no image, release or launcher command builds or starts it) |

## Workflows (`.github/workflows`)

| Workflow | Goal uses it | Action |
|---|---|---|
| `ci.yml`, `security.yml`, `scorecard.yml` | YES (gates) | KEEP |
| `release.yml`, `promote-stable.yml`, `release-recover.yml`, `pin-digests.yml` | YES (ship) | KEEP; deleted images removed from their lists |
| `security-scan-example.yml` | YES (example of `buggy-cli` in CI) | KEEP |
| `todo-to-issue.yml` | repo hygiene | KEEP |

## Docs and assets

| Group | Goal uses it | Action |
|---|---|---|
| `docs/{findings,quickstart,claude-code-agent,releasing,ci,evidence-and-probes,readiness,pipeline,bounty-programs,cli-reference}.md`, `docs/security/` | YES | KEEP |
| runtime docs (`agents`, `architecture`, `models`, `skills`, `skillogy`, `skill-schema`, `knowledge-graph`, `web-dashboard`, `setup-guide`, `getting-started`, `engagement-workflow`, `library-*`, `plugin-author-guide`, `contributor-architecture`, `makefile-reference`, `update-channels`, `agent-file-*`, `knowledge-retention`, `e2e-testing-guide`, `docs/tools/open-web.md`) | RUNTIME-ONLY | KEEP (K4); references to deleted areas removed |
| process docs (`COWORK`, `QUALITY_BAR`, `contributing`, ADR 0001–0004, 0012, template) | repo process | KEEP |
| `docs/offensive-vaccine.md`, `docs/features/blue-cell.md` | NO | DELETE |
| ADR 0005 (BloodHound), 0006 (agent-driven container lifecycle / opscontrol) | NO | DELETE |
| `docs/design/2026-06-04-bloodhound-kgstore-mapping.md`, `docs/design/2026-06-04-slither-kgstore-mapping.md` | NO | DELETE |
| `docs/architecture/red-team-infrastructure.md` (C2/redirectors), `docs/red-team/{ai-red-teaming,operations,tools-techniques,recon-methodology}.md`, `docs/buggy-architecture.html`, `docs/buggy-flow.html` | NO | DELETE |
| `docs/red-team/opplan-domain-knowledge.md` | RUNTIME-ONLY (`buggy_core/types/engagement.py` cites it for the OPPLAN schema) | DECIDE-K4 |
| `docs/integrations/reverse-skill.md` | NO | DELETE |
| `docs/benchmark-comparison.md` (XBOW numbers), `README-cybench/cybergym/exploitbench/mhbench`, `EXPLOITBENCH-GAINS.md` | NO | DELETE |
| `docs/mcp.md` (external MCP tool servers) | NO | DELETE with `tools/mcp` |
| `docs/research/*`, `docs/proposals/*`, `docs/RESEARCH_PHASE_C.md`, `docs/pypi-distribution-strategy.md`, `docs/skill-cleanup-*` | evaluation notes, plans | KEEP (history; not on any build path) |
| `README_KO.md` (translated README) | NO | DELETE |
| `assets/` marketing images/videos (`demo.mp4`, `demo.gif`, `main.png`, `issue*.png`, `buggy_infra.svg`, `cli.png`, `logo_banner.png`, `assets/benchmark/*`) | NO | DELETE those no kept doc references |

## Benchmark (`benchmark/`)

| Area | What it is for | Goal uses it | Action |
|---|---|---|---|
| `lab/` | local lab scoring of the hunt against Juice Shop / DVGA / DVWA | YES | KEEP |
| `RESULTS_POLICY.md`, `evidence.py`, `scorecard.py` | evidence-record contract for benchmark claims | YES (`docs/findings.md` cites the policy) | KEEP |
| `harness.py`, `runner.py`, `config.py`, `state.py`, `schemas.py`, `reporter.py`, `scorer.py`, `__main__.py`, `kg_*`, `combined-report.py`, `batch-run.sh`, `devin-stream.sh`, `providers/`, `configs/` | XBOW / Cybench / CyberGym / ExploitBench / MHBench harness | NO | DELETE |
| `cve_bench/` | CVE-Bench dry run | NO | DELETE |
| `dreadgoad/` | AD lab benchmark | NO | DELETE |
| `results/XBEN-*` | XBOW run outputs | NO | DELETE |

## Root files and scripts

| Item | Goal uses it | Action |
|---|---|---|
| `Makefile`, `pyproject.toml`, `uv.lock`, `langgraph.json`, `.env.example`, `config/` (LiteLLM) | YES / RUNTIME | KEEP; deleted targets/keys/graphs removed |
| `scripts/install.sh`, `install.ps1`, `ensure-stack-secrets.sh`, `next_version.py`, `check_*`, `init-*` | YES (install, gates) | KEEP |
| `scripts/render_benchmark_charts.py` | NO (renders XBOW charts) | DELETE |
| `scripts/init-web-db.sql`, `scripts/init_neo4j.cypher` | NO (superseded by `containers/postgres-init/01-create-web-db.sql` and the KG migrations) | DELETE |
| `scripts/check_defensive_workflows.py`, `scripts/check_skillogy_contracts.py` | manual smoke checks of kept code (`sandbox_kernel`, `skillogy`) | KEEP |
| `scripts/web-hotswap.sh` | RUNTIME-ONLY | KEEP (K4) |
| `integrations/agent-skills` | external agent skill for driving Buggy | RUNTIME-ONLY | KEEP (K4) |
| `board/` | task board | — | not touched |

## Deleted

Each row is one commit; `git revert <commit>` adds the area back (later
commits touched some of the same registry tables, so a revert can need a
small merge, and reverting an area that has skills needs `make
build-skill-graph` afterwards because the graph dump was regenerated once at
the end, in `59f837e`). Lines are text lines removed (binary files such as
images, videos and `package-lock.json` are counted as files only).

| Area | Files deleted | Lines removed | Lines added | Commit |
|---|---:|---:|---:|---|
| `clients/desktop` (Electron shell), its CI job, npm scripts, lockfile entries | 10 | 1,811 | 1 | `4ea22a8` |
| `mobile_operator` role + mobile skills | 8 | 1,512 | 1 | `b314d8d` |
| `wireless_operator` role + wireless skills | 11 | 1,959 | 1 | `cfe845c` |
| `iot_operator` role + IoT skills | 14 | 3,154 | 1 | `a1ef9ed` |
| `ics_operator` role + ICS skills | 3 | 349 | 0 | `fcbe290` |
| `osint_operator` role + OSINT skills | 3 | 361 | 8 | `ec6c986` |
| `forensicator` role + DFIR skills | 3 | 320 | 3 | `73d5c95` |
| `supply_chain_operator` role + supply-chain skills | 3 | 347 | 1 | `4f231a0` |
| `phisher` role + phishing skills | 14 | 2,119 | 5 | `d9417f6` |
| `postexploit` role + post-exploitation / lateral movement / privesc / C2 skills | 19 | 5,744 | 13 | `3233af9` |
| Command and control: Sliver image and entrypoint, `c2-sliver` service/profile/volume, sandbox Sliver client, release image lists, C2 infrastructure doc | 3 | 878 | 39 | `c915d9d` |
| Active Directory: `ad_operator`, `tools/ad`, AD skills, `bhce*` services/profile/volumes, BloodHound DB init, ADR-0005, BloodHound mapping design doc | 37 | 8,921 | 58 | `bc0042a` |
| (format fix-up after the postexploit commit) | 0 | 3 | 1 | `ca84c00` |
| Reverse engineering: `reverser`, `tools/reversing`, reverser skills, `ghidra-mcp` service and `reversing` profile, sandbox Ghidra build stage (`buggy-sandbox-reversing` image), binary triage tool | 42 | 8,108 | 46 | `0817dda` |
| Cloud: `cloud_hunter`, `tools/cloud`, cloud skills | 32 | 5,427 | 3 | `f2c7452` |
| Smart contracts / web3: `contract_auditor`, `tools/contracts`, contract skills, Solidity KG tools, Slither mapping design doc | 22 | 4,029 | 11 | `e204021` |
| Blue Cell and Offensive Vaccine: `blue_cell`, `buggy/blue_cell`, `tools/defense`, adversary-emulation skills, `docs/offensive-vaccine.md`, `docs/features/blue-cell.md` | 55 | 11,411 | 5 | `0097c9f` |
| `retrospective` role and its tools; the orchestrator's dead `task("retrospective")` step | 4 | 1,284 | 16 | `7a46851` |
| `asvs_assessor` role (duplicate of the bounty `asvs` role) | 4 | 396 | 4 | `e6bb652` |
| vulnresearch plugin bundle (`vulnresearch`, `scanner`, `detector`, `verifier`, `patcher`, `exploiter`), their prompts and skills (incl. `llm-redteam`) | 37 | 4,458 | 57 | `5042f83` |
| opscontrol dynamic-workload machinery: launcher daemon (`cmd/opscontrol`, `internal/opscontrol`) and its onboard/start/stop hooks, `tools/ops`, opscontrol notification middleware and slot, the orchestrator's workload section, ADR-0006 | 31 | 4,712 | 129 | `4470f77` |
| Benchmark harnesses other than `benchmark/lab` (XBOW, Cybench, CyberGym, ExploitBench, MHBench, Buttercup, CVE-Bench, DreadGOAD), XBOW results, the `solver` image/service, benchmark charts, `docs/benchmark-comparison.md` | 486 | 22,645 | 8 | `549141c` |
| Shared `defense-evasion` and `stealth-infra` skills | 4 | 1,624 | 2 | `eac2e86` |
| `tools/network` (no importers) | 4 | 2,433 | 0 | `be1642a` |
| `tools/mcp` (unwired external-MCP client) and `docs/mcp.md` | 4 | 690 | 0 | `2ffd52c` |
| README rewrite; `README_KO.md`; marketing assets (`assets/`) | 10 | 543 | 79 | `914c1a5` |
| Docs and agent prompts: references to deleted areas; red-team ops guides; architecture HTML diagrams | 6 | 2,228 | 131 | `3087d35` |
| Unused scripts (`init-web-db.sql`, `init_neo4j.cypher`) | 2 | 78 | 0 | `4aa5dca` |
| Skill graph dump regenerated; unused threat-actor overlay | 1 | 9,169 | 987 | `59f837e` |

## Kept, and why

- **`soundwave`** (planning agent) and **`skills/standard/soundwave`**: the
  launcher's engagement picker (`clients/launcher/internal/engagement/picker.go`),
  the web dashboard and `clients/cli` route new engagements to it. Removing it is
  a launcher/dashboard change, so it waits for K4.
- **The sandbox image's tool list** (`containers/sandbox.Dockerfile`: impacket,
  responder, netexec, adb, apktool, radare2, binwalk, …) and the matching
  capability registry entries in `buggy_core/capabilities.py`: the sandbox is part
  of the K4 runtime; only the Sliver client and the Ghidra stage (whose services
  were deleted) were removed.
- **KG schema for AD, Solidity and detection nodes** (`buggy_core/types/kg.py`)
  and the Neo4j migration `V003__bloodhound_and_slither_schema.cypher`: the
  migration chain of the K4 Neo4j store; dropping kinds changes the schema.
- **OPPLAN phases `post-exploit`, `c2`, `exfiltration`** and engagement type
  `physical` (`buggy_core/types/engagement.py`): part of the OPPLAN schema that
  `soundwave` writes; no agent now handles those phases.
- **Skillogy seed phases and MoCs** for deleted domains
  (`skillogy/builder/seeds/*.yaml`) and the skill-audit subdomain vocabulary:
  Skillogy is on the do-not-delete list; the seeds are data, not code paths.
- **HITL high-impact patterns for C2 tools** (`middleware/hitl.py`) and the
  interactive-prompt detection for `msf`/`sliver` prompts
  (`sandbox_kernel/tmux.py`): security controls and generic sandbox behaviour.
- **`docs/security/` as a whole**, including `sisyphus-pr.md` which describes
  the deleted Offensive Vaccine: the folder is on the do-not-delete list.
- **Historical ADRs, design notes, research and proposals** (`docs/adr/0009`,
  `0010`, `docs/design/*`, `docs/research/*`, `docs/proposals/*`,
  `CHANGELOG.md`): records of decisions; links in them to deleted ADRs are left
  as history.
- **`benchmark/RESULTS_POLICY.md`, `benchmark/evidence.py`,
  `benchmark/scorecard.py`**: `docs/findings.md` cites the policy; the XBOW
  wiring tests were removed from `test_evidence.py`, the record contract tests
  stay.
- **`.gitignore`, `.pre-commit-config.yaml`, `.typos.toml` patterns** for
  `assets/**` and `benchmark/results/**`: harmless ignore patterns; runs still
  write to `benchmark/results/`.

## Not deleted, needs a decision

- **`tools/research/tools.py` and the `RESEARCH_TOOLS` aggregate.** Since the
  plugin bundle is gone no agent loads `RESEARCH_TOOLS`; the kept roles import
  only `cve_lookup` and `allocate_finding_id` from that 2,400-line module, and
  `chain`, `dedupe`, `osint`, `patch`, `poc`, `sarif`, `scanner_tools`,
  `tech_detection`, `fuzz` are imported only through it. Pruning means splitting
  the module (and its tests); it belongs with the K4 runtime decision.
- **Compat shims** (`buggy/compat`, `buggy/plugin_loader.py`,
  `buggy/core/schemas.py` and the other re-export modules). Removing them means
  migrating every internal import to `buggy_core` and dropping
  `test_compat_shim_identity.py`; that is a migration, not a deletion.
- **Devin delegation** (`tools/devin`, `buggy_core/subscriptions.py`, the
  agent-subscription inventory in `llm/factory.py`, `buggy-cli auth`, the Devin
  bind mounts on the `langgraph` service). It is an optional reasoning path of
  the built-in runtime; whether the runtime keeps it is K4.
- **`BENCHMARK_MODE`** and `skills/benchmark`: the flag relaxes behaviour in
  `middleware/roe.py` and changes `middleware/engagement.py` and the KG tools.
  Removing it touches the RoE guardrail, so it is left for an explicit
  decision.
- **Capability delivery kinds `profile:` / `sidecar` and
  `requires_service` / `requires_profile`** in `buggy_core/capabilities.py`,
  and the profile/service rules in `readiness.py`: no shipped capability or
  domain uses them since the AD, C2 and reversing deletions (the readiness
  tests now exercise them with a synthetic domain). Removing them changes the
  buggy-core capability contract.
- **`mcp_server/` (`buggy-mcp`)**: drives LangGraph engagements for external
  MCP clients; it is runtime-only and waits for K4 with the runtime.

## Broken things found

- The orchestrator prompt told the model to `task("retrospective", ...)`, but
  `retrospective` was never registered as a subagent, so that call could not
  resolve. Removed with the role (`7a46851`).
- `packages/buggy/tests/test_capability_registry.py::test_promoted_tool_binaries_are_documented`
  asserted on post-exploit, reverser and DFIR skill files; it failed between
  the postexploit commit (`3233af9`) and the reversing commit (`0817dda`), which
  removed it once all three skills were gone.
- `engagement.py` was left unformatted by `3233af9`; fixed in `ca84c00`.

## Totals

| | Before (`6a90cab`) | After |
|---|---:|---:|
| Tracked files (`git ls-files \| wc -l`) | 2,510 | 1,640 |
| Lines (`git ls-files \| xargs wc -l`) | 586,002 | 385,077 |
| Container images built (release lists + `buggy-sandbox-reversing`) | 12 | 9 |
| Compose services in `docker-compose.yml` (all profiles) | 21 | 15 |
