# Running the agent stage with Claude Code (no model key)

Buggy's own agents need a model key. If you have Claude Code installed and
signed in, it can run the agent stage instead: it uses your Claude sign-in,
and no key is stored in Buggy.

```bash
buggy hunt https://your-target.example
```

When Buggy has no model configured and the `claude` command is on your PATH,
`buggy hunt` does this by itself: scope, recon, the probe sweep and the
access-control check run as code, then Claude Code runs the agent stage, then
the reports are rebuilt. To run only the agent stage on an engagement that
already exists:

```bash
buggy agent <engagement>
```

`--agent` on `buggy hunt` chooses who runs the agent stage:

| Value | Meaning |
|---|---|
| `auto` (default) | Buggy's agents when a model is configured; otherwise Claude Code if it is installed; otherwise the agent stage is skipped and the run says so. |
| `builtin` | Buggy's agents only. |
| `claude-code` | Claude Code, even if a model is configured. |

`--no-agent` and `--lite` never start an agent.

## What Claude Code can and cannot do here

Claude Code is started with **only** Buggy's tools and web search:

- Of its built-in tools it keeps web search alone (`--tools WebSearch`,
  allowed with `--allowedTools mcp__buggy,WebSearch`): no shell, no file
  access, and no `WebFetch`, which would fetch pages straight from your
  machine and so be a path to the target that bypasses the gateway.
- Other MCP servers configured on your machine are ignored
  (`--strict-mcp-config`).
- It runs in an empty temporary folder, so no project settings apply.
- It is never started with a permission bypass.

The tools come from the **agent bridge** (`python -m buggy.agent_bridge`),
which runs in the stack's operator container and offers the same tools the
built-in testing agents use: recon queries, `http_send`, `probe_run`, the
scoped browser, the findings tools, the shared board. The bridge is bound to
one engagement and one actor name (`claude-code`); the agent cannot name
another engagement, and never sees a server address, a token or a test
account's credentials.

What stays enforced, by the stack's servers and not by the agent:

- **Scope.** Every request is checked against the enforced scope.
- **Approvals.** A state-changing request or probe run returns
  `APPROVAL_REQUIRED` and is not sent. Only you approve
  (`buggy-cli approvals allow <engagement> <id>`); the agent is told never to.
- **Rate limit and ledger.** Every request is rate-limited and recorded.
- **Proof.** A claim becomes a finding only through `finding_verify`.

Three guards the built-in agents get from their middleware are applied by the
bridge before a call is forwarded:

1. your tool-call rules from the scope (`machine_enforcement.tool_guard`);
2. the same call three times in a row is withheld;
3. a cap on tool calls (`BUGGY_MAX_TOOL_CALLS`, default 300) for the whole
   agent stage, shared by its attempts (see "Several short attempts").

## Halting an engagement

```bash
buggy-cli halt <engagement> --reason "the client asked us to stop"
buggy-cli halt <engagement> --show
buggy-cli halt <engagement> --clear
```

A halt is a file, `<control>/<engagement>/HALT`, under the operator-only root;
no agent can write or remove it. While it is there:

- the bridge refuses every tool call (`HALTED`), tells the agent to write its
  summary, and closes, so Claude Code has no tools left;
- the evidence gateway sends nothing for the engagement (`HALTED`, with a
  ledger line), so Buggy's own agents, probes and retests stop too;
- the scoped browser loads nothing from the target.

Each halt also raises a counter, `<control>/<engagement>/halt-epoch`. A bridge
run notes the counter when it starts (its lease, kept in
`<audit>/<engagement>/agent/leases/<run>.json`), and a higher counter ends it
(`LEASE_REVOKED`). So `--clear` lets new runs start but never revives a run
that was going on when you halted. A halt state that cannot be read refuses
the call (fail closed).

## Several short attempts

The agent stage is up to three short Claude Code sessions instead of one long
one (`buggy agent --attempts N`, `buggy hunt --agent-attempts N`). Before each,
the launcher asks the bridge for the state (`python -m buggy.agent_bridge
--engagement X --status`: halt, calls used, open leads, as JSON). Another
attempt starts, in a fresh session, only when the last one finished cleanly,
leads are still open in `candidates_next`, attempts remain and the budget left
gives the attempt at least 15 calls. Each attempt gets an even share of what is
left; the bridge also caps a run at what the session's earlier attempts left.
A later attempt's brief lists the open leads and says that earlier "cannot be
done" conclusions were not proven by anything. A Claude Code failure (not
signed in, usage limit) is not retried.

## The disprover

After the attempts, when agent-made findings were verified (source not
`probe:` or `pipeline:`), a second Claude Code session runs the bridge with
`--role skeptic`. It has no web and no tool that sends a request: only
`finding_get`, `findings_list`, `http_capture` (only for captures a finding it
read cites), recon queries, the skill files, and `finding_challenge(finding_id,
verdict, reason)`. Its job is to argue each finding is false. Code decides the
effect: `false_positive` or `undetermined` holds the finding (grade rule 9,
not "submit") until you override it; `stands` changes nothing.

```bash
buggy-cli disprover list <engagement>
buggy-cli disprover override <engagement> <finding-id> --reason "cap-2 shows Alice's order"
```

The override is written under the operator-only root and the finding is
graded again. `hunt-result.json` records what the pass did (`"disprover":
"ran" | "nothing" | "skipped" | "failed"`). Buggy's own agents do not get this
pass; `buggy hunt` says so.

## What each run costs

The launcher runs Claude Code with `--output-format json` and records one line
per session in `<audit>/<engagement>/agent/agent-runs.jsonl`: tokens (input,
output, cache read and write), `total_cost_usd` when Claude Code reports it,
wall time, tool calls, refused calls, and calls spent signing in (identity
tools and requests to login, register, password, session or token URLs; a
heuristic). The agent's own text is not kept there. The line is written by the
status call that follows the session, inside the operator container, because
on Linux the audit root belongs to the containers' user. The launcher prints a
short line after each session. `hunt --finalize` adds an "Agent cost" line to
`hunt-result.json` (`agent_cost`), `report.md` and the Word report. When
Claude Code reports no cost, the line says so.

The bridge's call log, its leases and these lines live in
`<audit>/<engagement>/agent/`. The operator container mounts the audit root
read-only, so the launcher mounts that one folder writable for the bridge and
its status call (`BUGGY_AGENT_RECORDS`).

## Reading the traces

The bridge writes one line per tool call to
`<audit>/<engagement>/agent/calls.jsonl`: tool, a digest of the arguments
(not the arguments), refusal code, time, run and session, capture ids seen in
the result, and the captures a `finding_submit` cites. `buggy-cli trace-review
<engagement>` (add `--json` for JSON) flags, by fixed rules:

- loops: the same call three times or more in a run;
- dead ends: six calls in a row that were refused, failed or repeated an
  earlier answer;
- no progress: 40 calls in a row without a submitted or verified finding, a
  fact or a saved recipe;
- invented observations: a `finding_submit` citing a capture no tool had
  returned earlier in the session;
- refusals per run, with a warning when policy refusals (scope, internal
  address, operator rule, target data in a URL) cluster: four within ten
  calls is an early sign of a prompt injection steering the agent.

`hunt --finalize` prints its one-line summary.

For the lab benchmark's plain-agent baseline, `BUGGY_AGENT_PROFILE=plain`
gives the bridge a smaller set: `http_send`, `http_capture` and the finding
tools, and a brief with the rules, the budget and the targets only. See
`benchmark/lab/README.md`.

## Skill files

The agent can read Buggy's skill files with two read-only tools (no network,
no target, offered with or without `--no-web`):

- `skill_list` finds skills by words (`sql injection`, `jwt`, `cache`);
- `skill_get` returns one whole skill.

89 of them, one per web bug, were written from HackTricks' `/pentesting-web`
section and live under
`packages/buggy/buggy/skills/standard/exploit/web/hacktricks/<slug>/SKILL.md`,
named `web-<slug>`. Each says what the bug is, where to look (which recon
records point to it), how to test it step by step (read-only first, writes
marked "needs approval"), payloads and bypasses, how to prove it, false
positives, which Buggy check covers it, what not to do, and the fix, with the
HackTricks pages it came from. `web-web-vulnerabilities-methodology` is the
index. 69 more, named `web-tech-<slug>`, cover one technology each (Tomcat,
WordPress, Spring Actuators, Next.js and so on).

How the agent is pointed at the right skill (all fixed rules in
`buggy/findings/skill_map.py`, no model):

- **Each lead names its skills.** `candidates_next` adds `skills` to every
  lead: the probe that raised it (`sqli` -> `web-sql-injection`), words in its
  endpoint and description (`reset` -> `web-reset-password`, `wp-login.php`
  -> `web-tech-wordpress`), then its bug class. At most four; the index when
  nothing fits.
- **The brief names the technology skills.** After recon, `hunt` writes
  `<control>/<engagement>/technologies.json` (what httpx saw and the matching
  `web-tech-*` skills); the agent's brief lists both.
- **Read only what is needed.** `skill_get` takes `section`, e.g.
  `section="how to test"` or `section="prove, do not"`.
- **No finding without its skill.** The bridge refuses `finding_submit` for a
  bug class until the agent has read one of that class's skills in this run,
  and names the skill and the sections to read.
- **Skills cannot name checks that do not exist.** A test checks every Buggy
  check a skill's "In Buggy" section names against the probe registry and the
  agent tools, and that every skill the map hands out exists.
- **Skills have versions.** `packages/buggy/buggy/skills/skills.lock.json`
  holds every SKILL.md's sha256 and the digest that last passed
  `uv run python -m buggy.skill_audit verify-skills` (frontmatter valid,
  sections complete, every Buggy check it names exists). `skill_get` names the
  digest it served in its first line, so a run records which version it read.
  `skill_list` marks a skill `unverified` when its file changed since then.
  `make check-skills-lock` (in CI) fails when a skill changed without the lock
  being updated; after editing a skill, run `make verify-skills` and commit
  the lock (`... skill_audit lock --write` only rewrites the digests).

HackTricks allows adapting its content with attribution; commercial use needs
its author's permission.

## Looking things up on the public internet

The agent can look up public reference material: the documentation of a
framework it met, a CVE write-up, an API reference.

- **Search** is Claude Code's own web search. The query goes from Claude Code
  to Anthropic's search service, not through Buggy.
- **Reading a page** goes through the bridge's `research_fetch` tool, which
  runs in the operator container and counts against the call cap like every
  other tool (the repeat guard and your tool-call rules apply too). It sends
  a bare GET (fixed User-Agent `buggy-research/1`, no cookies, no
  credentials), follows at most five redirects and re-checks every hop.
  It refuses, before anything is sent:
  - the target: a host the enforced scope allows, a host an out-of-scope
    entry names, any host under an in-scope host's domain or its parent
    (`app.acme.com` makes all of `acme.com` off limits), and a name that
    resolves to one of the target's addresses (`IN_SCOPE_USE_GATEWAY`; the
    target is reached only through `http_send`);
  - internal addresses, by name and after DNS resolution, with the
    gateway's rule; the name is resolved once and the connection goes to the
    address that was checked (`INTERNAL_ADDRESS`);
  - userinfo in the URL, a bare IP address, a port other than 80, 443, 8080
    or 8443, or a URL over 2,000 characters (`BAD_URL`);
  - a URL whose path or query contains an in-scope host name, an email
    address or a long token-like value (`LOOKS_LIKE_TARGET_DATA`).

  Only text, HTML (reduced to readable text with its links), JSON, XML and
  PDF (size only, not parsed) are read. The result is marked as reference
  material, not instructions. Each call adds one line (URL, final URL, status
  or refusal, size; never the page) to `<audit>/<engagement>/research.jsonl`;
  where the audit root is read-only, as in the operator container, the line
  goes to the bridge's log instead.

What is **not** enforced by code: a search query is typed by the model and
sent by Claude Code, so Buggy never sees it. The rule against putting the
target's host names, data or tokens into a query is an instruction in the
brief, not a filter. If that is not acceptable for an engagement, turn the
web off:

```bash
buggy hunt https://your-target.example --no-web
buggy agent <engagement> --no-web
```

`--no-web` starts Claude Code with `--tools ""` (no built-in tool at all) and
tells the bridge (`BUGGY_AGENT_WEB=off`) to leave `research_fetch` out.

## After the run

`buggy hunt` and `buggy agent` finish with
`buggy-cli hunt --resume <engagement> --finalize`, which rebuilds
`hunt-result.json` and the reports from the findings store without running
anything again. `hunt-result.json` records `"agent": {"ran": true, "runner":
"claude-code"}`, and `--fail-on` works as usual.

If Claude Code stops early (not signed in, usage limit), whatever it had
already proven is kept; run `buggy agent <engagement>` again to continue.

## Running it by hand (source checkout)

Write an MCP configuration that starts the bridge through your compose
command, then start Claude Code with only that server:

```json
{
  "mcpServers": {
    "buggy": {
      "command": "docker",
      "args": ["compose", "--profile", "operator", "run", "--rm", "-T", "operator",
               "python", "-m", "buggy.agent_bridge", "--engagement", "<engagement>"]
    }
  }
}
```

```bash
claude -p "Call the engagement_brief tool of the buggy server, then carry out the engagement it describes using only that server's tools." --mcp-config mcp.json --strict-mcp-config --tools WebSearch --allowedTools mcp__buggy,WebSearch
```

For a run with no web access use `--tools "" --allowedTools mcp__buggy` and
add `"-e", "BUGGY_AGENT_WEB=off"` after `"-T"` in the configuration's `args`.
The operator container mounts the audit root read-only, so a hand-started
bridge cannot keep its call log and lease there (it warns once and keeps none);
`buggy agent` mounts `<audit>/<engagement>/agent` writable for that. A run
started this way is one attempt with no disprover.

Run it from the repository root (where `docker-compose.yml` and `.env` are),
then close the run:

```bash
docker compose --profile operator run --rm operator buggy-cli hunt --resume <engagement> --finalize --agent-runner claude-code --yes
```

## Limits

- Usage counts against your own Claude plan. Buggy records what Claude Code
  reports per session (tokens, cost) but does not cap spend in dollars.
- The agent's quality on real programs has not been measured here. Two
  bounded runs against the local practice apps are recorded in
  [findings.md](findings.md).
- Buggy's role-specific sub-agents and skills are not used in this mode: one
  Claude Code agent works the queue.
- The lite stack has no evidence gateway, so it cannot run an agent stage.
