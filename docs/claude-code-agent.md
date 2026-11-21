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

Claude Code is started with **only** Buggy's tools:

- Its built-in tools are turned off (`--tools ""`): no shell, no file access,
  no web access.
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
claude -p "Call the engagement_brief tool of the buggy server, then carry out the engagement it describes using only that server's tools." --mcp-config mcp.json --strict-mcp-config --tools "" --allowedTools mcp__buggy
```

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
