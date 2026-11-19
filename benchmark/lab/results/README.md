# Lab results — 2026-11-19

Apps: Juice Shop v17.1.1 and DVGA. DVWA and crAPI have ground truth but were
not run. The XBOW benchmark was not run.

| Class | Known | pipeline only | probes (lab-tested) | agent + pipeline | agent, no pipeline |
|---|---:|:---:|:---:|:---:|:---:|
| auth_session | 4 | 0/4 | 1/4 | not run | not run |
| access_control | 6 | 0/6 | 2/6 | not run | not run |
| ssrf | 2 | 0/2 | 1/2 | not run | not run |
| business_logic | 2 | 0/2 | 1/2 | not run | not run |
| api | 2 | 0/2 | 1/2 | not run | not run |
| graphql | 4 | 2/4 | 2/4 | not run | not run |
| injection | 6 | 0/6 | 0/6 | not run | not run |
| xss | 3 | 0/3 | 0/3 | not run | not run |
| file_handling | 2 | 0/2 | 0/2 | not run | not run |
| csrf | 1 | 0/1 | 0/1 | not run | not run |
| open_redirect | 1 | 0/1 | 0/1 | not run | not run |
| crypto | 1 | 0/1 | 0/1 | not run | not run |
| misconfiguration | 2 | 1/2 | 0/2 | not run | not run |
| info_exposure | 4 | 3/4 | 0/4 | not run | not run |

| Baseline | Seconds | LLM calls | Tokens | Cost (USD) |
|---|---:|---:|---:|---:|
| pipeline only | 529.3 | 0 | 0 | 0.0 |
| probes (lab-tested) | see lab tests | 0 | 0 | 0.0 |
| agent + pipeline | not run | not run | not run | not run |
| agent, no pipeline | not run | not run | not run | not run |

## What was run

- **pipeline only** — a real run of the pinned pipeline image against both
  apps on the lab network (`2026-11-19-pipeline.json`): 529 s, 0 LLM calls.
  It matched 6 of 40 known entries, missed 34, and reported 30 items with no
  ground-truth entry (missing security headers, cookie flags, technology
  fingerprints, GraphQL batching — real observations, low value).
- **probes** — 8 entries are reproduced by `packages/buggy/tests/lab`
  (15 tests including negative controls, all passing against the live apps).
- **agent arms** — not run: the environment this was produced in has no model
  provider credentials. Found / missed / false positive, cost, time, and the
  token comparison with vs without the pipeline are therefore unmeasured.

## Reading

Strong without any LLM: exposed surfaces and misconfiguration
(`info_exposure` 3/4, `misconfiguration` 1/2, GraphQL introspection and field
suggestions).

Weak for the pipeline, by design — these need an identity, a second account or
a state change: `auth_session`, `access_control`, `ssrf`, `business_logic`,
`api`. Each now has a deterministic probe that finds one known instance once
it is aimed at the right endpoint.

Not covered by the pipeline or any probe: `injection` (0/6), `xss` (0/3),
`file_handling` (0/2), `csrf`, `open_redirect`, `crypto`. These are agent-only
until the agent arms are measured.
