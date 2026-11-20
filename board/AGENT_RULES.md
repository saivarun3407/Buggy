# Rules for every task agent

You are finishing ONE task from `board/tasks/<ID>.md`. Read that file, this file and
`board/CONTRACTS.md` before writing anything.

## Non-negotiable

1. **Build what the task says, nothing else.** If the spec is wrong or impossible, stop and
   report why. Do not redesign, rename, or widen the task.
2. **No gaming.** A test must exercise real behaviour and must be able to fail. Every
   "detects X" test needs a negative control that proves it does not flag a safe case.
   Never weaken, skip or delete an existing test to get green. Never hard-code an expected
   answer for a fixture into product code.
3. **Deterministic first.** If code can do it, it is code. No LLM calls in anything you build.
4. **Touch only the files your task lists under "Files you own".** Other files are owned by
   other agents working at the same time. If you believe you must change another file, stop
   and report it instead.
5. **Dependencies:** modules under `buggy/pipeline`, `buggy/capture`, `buggy/findings`,
   `buggy/memory`, `buggy/coordination` run in a slim image: standard library plus
   `buggy_core`, `pydantic`, `pyyaml`, `mcp` only. No `langchain`, `httpx`, `requests`.
6. **Safety properties are not yours to relax.** Scope checks, approval holds, the capture
   ledger and redaction must keep working. Anything that sends a request to a target goes
   through `CaptureGateway.send`.

## Working

- You are in your own git worktree. First command: `uv sync --extra neo4j --extra mcp` (if it
  fails, retry once; the proxy is slow).
- Run tests with `uv run pytest <paths> -q -p no:cacheprovider`. Run the tests you wrote plus
  the existing suite of every package you touched.
- Lint before committing: `uv run ruff check --fix <paths>` and `uv run ruff format <paths>`.
- Do **not** run `docker compose`, start containers, or run `tests/e2e`. One shared lab is
  already running. Lab tests reach it through these variables (export them for lab tests):
  `BUGGY_LAB=1`, `BUGGY_LAB_JUICE_URL`, `BUGGY_LAB_DVGA_URL`, `BUGGY_LAB_CANARY_HOST` — the
  values are in your prompt. The lab apps are shared with other agents: create your own
  accounts and objects, never depend on a clean state, never run destructive requests.
- Commit on your worktree branch with a message `<ID>: <what changed>`. Do not push, do not
  merge, do not touch `board/`.

## Report back (your final message, plain text)

```
TASK: <ID>
STATUS: done | blocked
BRANCH: <git branch name>      COMMIT: <sha>
FILES: <list>
TESTS RUN: <exact commands and pass/fail counts>
NOT DONE / DEVIATIONS: <anything the spec asked for that you did not do, and why>
INTEGRATION NOTES: <what the integrator must wire: tool names, env, compose, docs>
```

If you are blocked, say exactly what is missing. A truthful "blocked" is a good result; a
green test that proves nothing is not.

## No key-shaped literals

GitHub push protection rejects commits that contain strings shaped like real provider keys (Stripe `sk_live_...`, GitHub `ghp_...`, Slack `xox...`, AWS, Google). Test fixtures that need such a value must build it at runtime (`"sk_" + "live_" + "..."`), never as one literal.
