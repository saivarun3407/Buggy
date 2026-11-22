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
3. a cap on tool calls per run (`BUGGY_MAX_TOOL_CALLS`, default 300).

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

Run it from the repository root (where `docker-compose.yml` and `.env` are),
then close the run:

```bash
docker compose --profile operator run --rm operator buggy-cli hunt --resume <engagement> --finalize --agent-runner claude-code --yes
```

## Limits

- Usage counts against your own Claude plan; Buggy does not measure it.
- The agent's quality on real programs has not been measured here. One
  bounded run against the local practice apps is recorded in
  [findings.md](findings.md).
- Buggy's role-specific sub-agents and skills are not used in this mode: one
  Claude Code agent works the queue.
- The lite stack has no evidence gateway, so it cannot run an agent stage.
