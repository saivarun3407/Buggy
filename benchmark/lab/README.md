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
