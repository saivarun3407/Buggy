# Lab capability baseline

Measures what Buggy finds, per vulnerability class, against local
intentionally-vulnerable applications only. Nothing here touches a real
target: the lab network is Docker-internal and the lab scope lists the lab
hostnames and nothing else.

| App | Image | Ground truth |
|---|---|---|
| OWASP Juice Shop | `bkimminich/juice-shop:v17.1.1` | `ground_truth/juice-shop.json` |
| DVGA (GraphQL) | `dolevf/dvga` | `ground_truth/dvga.json` |
| DVWA | `vulnerables/web-dvwa` | `ground_truth/dvwa.json` |
| crAPI | upstream compose | `ground_truth/crapi.json` |

Denial-of-service scenarios are marked `prohibited` in the ground truth: never
tested, never counted as missed.

## Run it

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d juice-shop dvga
```

```bash
uv run python -m benchmark.lab scope --engagement lab
```

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml run --rm pipeline run lab
```

```bash
uv run python -m benchmark.lab pipeline-baseline --engagement lab --data-root <recon store dir>
```

```bash
BUGGY_LAB=1 uv run pytest packages/buggy/tests/lab
```

```bash
uv run python -m benchmark.lab agent-run --engagement lab-a --arm with-pipeline
```

```bash
uv run python -m benchmark.lab agent-run --engagement lab-b --arm without-pipeline
```

```bash
uv run python -m benchmark.lab report
```

The two agent arms need a model provider key and the full stack running. They
record LLM calls, tokens and cost from the LiteLLM spend log before and after
the run; the difference between the arms is the token cost of doing recon with
an agent instead of the pipeline.

## Columns

- **pipeline only** — records the deterministic pipeline produced that match a
  ground-truth entry's `pipeline_signals`. No LLM.
- **probes (lab-tested)** — entries whose `verified_by` names a test in
  `packages/buggy/tests/lab`: a deterministic probe was run against the real
  app and the test asserts the bug is reported. No LLM. The probe still has to
  be pointed at the right endpoint and accounts; choosing those is the agent's
  job.
- **agent + pipeline / agent, no pipeline** — findings an agent run emitted,
  matched to ground truth by class, location and keywords.

`unmatched` in a result file counts reported items that match no ground-truth
entry. Ground truth is not exhaustive, so unmatched is an upper bound on false
positives, not a count of them.

Results: [`results/README.md`](results/README.md).

## Stage evaluation of a hunt run

`evaluate` scores one finished `buggy hunt` run against the ground truth, stage
by stage, from the run's own files. It sends nothing to a target.

```bash
uv run python -m benchmark.lab evaluate --engagement <name> \
  --control-root ~/.buggy/control --audit-root ~/.buggy/audit --data-root <data folder>
```

The data folder holds `recon.sqlite3` and `findings.sqlite3` (and
`captures.sqlite3`, `recipes.sqlite3` if present). In the full stack they live
in Docker volumes; copy them out read-only, for example from
`docker volume inspect -f '{{.Mountpoint}}' buggy-full_pipeline_data` and
`buggy-full_capture_data`.

Per ground-truth entry it gives five stages, each judged on its own:

- **recon**: a recon record covers the entry's location or its signals;
- **lead**: the findings store holds a lead or claim of its class there;
- **attempt**: a probe or recipe of its class, or the agent's own request,
  reached the location (a proof also counts);
- **proof**: an exploit-verified finding fits it;
- **report**: that finding is in the report graded `submit` (the found count).

A missed entry gets the label of the furthest stage it reached:
`not_in_recon`, `no_lead`, `not_attempted`, `attempted_not_proven` (with the
probes that ran), `proven_but_held`; `prohibited` entries are never tested.

Scope adherence is reported apart from the results, from the gateway ledger:
requests sent, refused as out of scope, refused as internal, held for approval,
and any request to a host outside the scope, which is a hard failure. The
ledger's hash chain is checked too.

The Juice Shop scoreboard (`/api/Challenges`) is read only when the lab app is
running and its host resolves to a private address; otherwise the scorecard
says it was skipped. Solved challenges are listed apart and never counted as
Buggy's findings.

The run directory `results/<hunt date>-<engagement>/` holds `inputs.json` (what
was read, reduced: hosts and paths only, no bodies), `evaluation.json`,
`manifest.json` (input file hashes) and the generated `SCORECARD.md`. Check it:

```bash
uv run python -m benchmark.lab verify benchmark/lab/results/<run-id>
```

`verify` re-evaluates `inputs.json` and re-renders the scorecard; any edited
number fails it.

## Plain-agent baseline

The baseline arm is Claude Code with only `http_send` and the finding tools: no
recon, leads, probes, recipes, browser, skills or web, and the same tool-call
budget as the Buggy arm. The bridge offers this set with
`BUGGY_AGENT_PROFILE=plain`. Print the steps (nothing runs):

```bash
uv run python -m benchmark.lab plain-agent --engagement plain1 --apps juice-shop --tool-budget 300
```

`--execute` writes the scope and starts Claude Code; it needs the full stack,
the lab apps and a signed-in Claude Code. Score it with `evaluate --arm
plain-agent --tool-budget 300`, then put two runs side by side:

```bash
uv run python -m benchmark.lab compare results/<run-a> results/<run-b> --write results/<a>-vs-<b>
```

The comparison covers the apps both runs evaluated and says whether compute was
equal (same stated model and tool-call budget). Buggy's recon and probes cost
requests but no model calls; requests sent are shown for both arms.
