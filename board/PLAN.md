# Plan: every criterion to 3, built for real

Source of the scores: `docs/research/offsec-harness-top10-evaluation-2026-11-19.md`.
Method: for each criterion, look at what the tools scoring 3 actually do (their READMEs and docs, read on 2026-11-19), take the mechanism, and build it as deterministic code with tests that can fail. No score is raised by wording.

Two things on this board cannot be finished by writing code, and are marked as such:
- **Published results (E08):** the harness and evidence contract can be built; the numbers need a model key and a real run (card X1, blocked).
- **Time to first result (E01):** the lite stack and commands can be built and tested; the public install script and published images are outside this repository's tests.

| Epic | Criterion | Now | Target | Leaders | Cards |
|---|---|:-:|:-:|---|---|
| E01 | Time to first result | 1 | 3 | Shannon, Strix, Xalgorix | A1, A2, A3, A4, A5 |
| E02 | Recon by code, not the model | 3 | 3 | RedAmon (Buggy already 3) | B1, B2, B3, B6 |
| E03 | Scope enforced technically | 3 | 3 | RedAmon, Hacker Bob (Buggy already 3) | D5 |
| E04 | Approval before state changes | 3 | 3 | RedAmon, CyberStrikeAI (Buggy already 3) | D4 |
| E05 | Findings proven before reporting | 2 | 3 | Shannon, Xalgorix, Hacker Bob | E1, E2, E3 |
| E06 | Evidence and audit trail | 3 | 3 | CyberStrikeAI, RedAmon (Buggy already 3) | D3 |
| E07 | Memory and knowledge | 2 | 3 | RedAmon, PentAGI, Cairn | B5, F1, F2 |
| E08 | Published results | 1 | 3 | RedAmon, Hacker Bob | C5, F3, X1 |
| E09 | Web and API depth | 2 | 3 | Shannon, Strix, Xalgorix | B4, C1, C2, C3, C4, D1, D2 |
| E10 | Breadth beyond web | 2 | 3 | CyberStrikeAI, HexStrike, Decepticon | F4 |
| E11 | Reports and developer workflow | 2 | 3 | Shannon, Strix, Xalgorix, RedAmon | E4, E5, E6 |
| E12 | UI, API, observability | 1 | 3 | RedAmon, PentAGI, CyberStrikeAI | A6, F6 |
| E13 | Bug-bounty program support | 3 | 3 | Buggy leads; h1-brain, Hacker Bob adjacent | F5 |
| INT | Integration and proof | — | 3 | — | I1, I2, I3 |

## E01 — Time to first result

**What the leaders do right (Shannon, Strix, Xalgorix):**

- Two commands from install to report (Shannon: `setup` wizard, then `start`)
- Resume by re-using the workspace name; partial scans retry only what failed
- `status --json` and per-agent logs while it runs
- Headless mode with exit codes for CI (Strix `-n`)
- A setup step that validates before running (`--validate-auth`)

**What Buggy builds:** Preflight (`doctor`), a two-service lite stack that needs no model, a bundled demo target, `status`, resume and exit codes.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [A1](tasks/A1.md) | `buggy-cli doctor`: preflight that says exactly what is missing | A | — |
| [A2](tasks/A2.md) | `buggy-cli status <engagement>`: one snapshot of a run, with `--json` and `--follow` | A | — |
| [A3](tasks/A3.md) | Lite stack: recon and report with two services | A | — |
| [A4](tasks/A4.md) | Launcher: `buggy hunt --lite`, `buggy doctor`, `buggy demo` | A | A1, A3 |
| [A5](tasks/A5.md) | `hunt`: resume, exit codes for CI, and a machine-readable result file | A | A2 |

## E02 — Recon by code, not the model

**What the leaders do right (RedAmon (Buggy already 3)):**

- Coverage stamps so a missing finding is never read as clean
- Wildcard-DNS probe with random names
- Parameter nodes; JS recon with ~100 patterns, source maps, DOM sinks
- LLM decisions only as a cascade after a deterministic path

**What Buggy builds:** Keep the lead: coverage stamps, wildcard filter, parameter records, deeper JS analysis.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [B1](tasks/B1.md) | Coverage stamps: a missing result is never read as clean | B | — |
| [B2](tasks/B2.md) | Wildcard DNS filter | B | B1 |
| [B3](tasks/B3.md) | Parameter records: every input the target accepts, as data | B | B2 |
| [B6](tasks/B6.md) | JavaScript analysis: source maps, DOM sinks, dependency names | B | B5 |

## E03 — Scope enforced technically

**What the leaders do right (RedAmon, Hacker Bob (Buggy already 3)):**

- CyberStrikeAI tool guard: ordered rules over every argument, percent-decoded, right before execution, independent of approvals
- Dry-run endpoint for a rule

**What Buggy builds:** Extend the forbidden-pattern check to every tool and argument, with decoding and a dry run.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [D5](tasks/D5.md) | Tool-call guard: ordered rules over every argument, decoded, before execution | D | D4 |

## E04 — Approval before state changes

**What the leaders do right (RedAmon, CyberStrikeAI (Buggy already 3)):**

- Approve / reject / edit in the UI (RedAmon)
- Notifications when something waits (Xalgorix, Strix Cloud)

**What Buggy builds:** Tell the operator: webhook / Slack / Discord notifications; approve from the dashboard (A6).

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [D4](tasks/D4.md) | Notifications: tell the operator when something waits for them | D | D3 |

## E05 — Findings proven before reporting

**What the leaders do right (Shannon, Xalgorix, Hacker Bob):**

- 'No exploit, no report': only status `exploited` reaches the report and the CI gate (Shannon)
- A separate verifier re-exploits every candidate; inconclusive is flagged, never confirmed (Xalgorix)
- Labels: exploit-verified vs source-verified
- Reconcile all candidate streams into one deduplicated queue (Shannon)
- VERIFY then GRADE: submit / hold / discard (Hacker Bob)

**What Buggy builds:** Findings with machine-checkable assertions, an independent verifier, a grader, one candidate queue.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [E1](tasks/E1.md) | Findings store and an independent verifier (`exploit_verified` or it is not a finding) | E | — |
| [E2](tasks/E2.md) | Grade: submit, hold or discard, with stated reasons | E | E1 |
| [E3](tasks/E3.md) | Candidate queue: one deduplicated list of things to prove | E | E2 |

## E06 — Evidence and audit trail

**What the leaders do right (CyberStrikeAI, RedAmon (Buggy already 3)):**

- Step-by-step replay of an attack chain (CyberStrikeAI)
- Scratchpad of scripts per finding (Shannon)

**What Buggy builds:** Evidence bundle per finding: HAR, runnable curl, ledger excerpt, hash manifest.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [D3](tasks/D3.md) | Evidence bundle: a reproducible package per finding | D | D2 |

## E07 — Memory and knowledge

**What the leaders do right (RedAmon, PentAGI, Cairn):**

- Recon writes a graph the agent traverses: Domain -> Subdomain -> IP -> Port -> Service -> Endpoint -> Parameter -> Vulnerability (RedAmon)
- Per-run memory separate from reusable guide / answer / code knowledge, retrieved with a threshold and a limit of 3 (PentAGI)
- Facts (append-only), Intents (claimed with a heartbeat lease), Hints; workers coordinate only through the board (Cairn)

**What Buggy builds:** Project recon into the graph; a cross-engagement lessons store; a fact / intent / hint board.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [B5](tasks/B5.md) | Project the recon store into the knowledge graph | B | B4 |
| [F1](tasks/F1.md) | Lessons: what worked and what failed, kept across engagements | F | — |
| [F2](tasks/F2.md) | Fact / intent / hint board: agents coordinate through shared state, not chat | F | F1 |

## E08 — Published results

**What the leaders do right (RedAmon, Hacker Bob):**

- Per-target raw transcript, model, wall time and tokens, failures listed (RedAmon)
- A self-critical coverage audit: complete / backlog / excluded per class
- Historical results labelled as historical (PentestGPT)
- Real-world receipts with links, pending marked pending (Hacker Bob)

**What Buggy builds:** An evidence contract and verifier for benchmark runs, a coverage audit that sums. The run itself needs a model key.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [C5](tasks/C5.md) | Coverage audit: one explicit verdict per vulnerability class and known bug | C | C4 |
| [F3](tasks/F3.md) | Benchmark evidence contract: results anyone can check | F | F2 |
| [X1](tasks/X1.md) | Run the agents on the lab and XBOW suites and publish verifiable results | X | I3, F3 |

## E09 — Web and API depth

**What the leaders do right (Shannon, Strix, Xalgorix):**

- Five specialist classes: injection, XSS, SSRF, authentication, authorization (Shannon)
- Declarative login flow with TOTP and a success condition, validated first (Shannon)
- OpenAPI / Postman contracts as input so every declared endpoint is tested (Strix)
- 22 phases including IDOR, race conditions, open redirect, CORS (Xalgorix)

**What Buggy builds:** Deterministic probes for SQLi, XSS, SSTI, command injection, redirect, traversal, CORS; identities and an authorization matrix; operator-supplied contracts.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [B4](tasks/B4.md) | Operator-supplied API contracts (OpenAPI, Postman) | B | B3 |
| [C1](tasks/C1.md) | SQL injection probe (boolean, error and time based, with controls) | C | — |
| [C2](tasks/C2.md) | Reflected XSS probe with context analysis | C | C1 |
| [C3](tasks/C3.md) | Server-side template injection and OS command injection probes | C | C2 |
| [C4](tasks/C4.md) | Open redirect, path traversal and CORS probes | C | C3 |
| [D1](tasks/D1.md) | Identities: declarative login and multi-role sessions the agent never sees | D | — |
| [D2](tasks/D2.md) | Authorization matrix: every endpoint against every identity | D | D1 |

## E10 — Breadth beyond web

**What the leaders do right (CyberStrikeAI, HexStrike, Decepticon):**

- 100-150+ tools by category; health endpoint with tool availability (HexStrike)
- Missing tools are skipped or substituted, visibly (CyberStrikeAI)

**What Buggy builds:** Buggy inherits the breadth. Verify it: a tool and domain readiness matrix from the real sandbox.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [F4](tasks/F4.md) | Tool and domain readiness matrix: know what actually works before a run | F | F3 |

## E11 — Reports and developer workflow

**What the leaders do right (Shannon, Strix, Xalgorix, RedAmon):**

- PDF + Markdown + JSON + SARIF, validated findings only (Shannon)
- GitHub Action with `fail-on-severity` and SARIF upload; incomplete is not clean (Shannon)
- CVSS, PoC and remediation per finding (Xalgorix)
- Fix loop: PRs and retest (RedAmon CypherFix, Strix Cloud)

**What Buggy builds:** One report over verified findings in Markdown, HTML, JSON; SARIF; a CI gate and Action; retest.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [E4](tasks/E4.md) | Report: Markdown, self-contained HTML and JSON from one finding schema | E | E3 |
| [E5](tasks/E5.md) | SARIF 2.1.0, a CI gate, and a GitHub Action | E | E4 |
| [E6](tasks/E6.md) | Retest: prove a fix with the same proof | E | E5 |

## E12 — UI, API, observability

**What the leaders do right (RedAmon, PentAGI, CyberStrikeAI):**

- Live run page: phase, tool activity, findings (PentAGI, RedAmon)
- Approve / deny inline; stop and steer (RedAmon)
- Execution monitor: repeated tool calls trigger an intervention; per-role caps (PentAGI)
- Traces of LLM and tool calls with cost (PentAGI)

**What Buggy builds:** A run page in the dashboard (recon, approvals, findings); a loop guard; per-run telemetry.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [A6](tasks/A6.md) | Dashboard: engagement run page (recon, approvals, evidence, findings) | A | A2 |
| [F6](tasks/F6.md) | Run telemetry and a loop guard: see cost and stop wasted work | F | F5 |

## E13 — Bug-bounty program support

**What the leaders do right (Buggy leads; h1-brain, Hacker Bob adjacent):**

- `hack(handle)` briefing: fresh scope, weaknesses that paid, untouched scope, suggested vectors (h1-brain)
- Grade for submission (Hacker Bob)

**What Buggy builds:** A program brief from scope, recon and report history; duplicate risk.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [F5](tasks/F5.md) | Program brief: where to look first on a bounty program | F | F4 |

## INT — Integration and proof

**What the leaders do right (—):**

- Nothing counts until it runs on the real stack

**What Buggy builds:** Wire, ship, verify.

| Card | Task | Lane | Depends on |
|---|---|:-:|---|
| [I1](tasks/I1.md) | Integration: expose the new capabilities to agents through the stack's MCP servers | I | D5, E6, F6, B6, C5 |
| [I2](tasks/I2.md) | Integration: images, compose, secrets root, docs | I | I1 |
| [I3](tasks/I3.md) | Verification: full suite, scope e2e, lab probes, and a live hunt on the real stack | I | I2 |

## How the work runs

- Six lanes (A–F), one agent per lane at a time, each task in its own git worktree. Lanes own disjoint files, so merges do not conflict.
- Each card is a spec in `board/tasks/`: why, idea, architecture, files owned, out of scope, tests, done-when. Agents follow `AGENT_RULES.md` and build against `CONTRACTS.md`.
- A card moves Ready → In progress → Review (merged, tests re-run on the main tree) → Done. A card that fails review goes back with the failure.
- Integration (I1–I3) is done serially at the end and finishes with a run on the real stack.
