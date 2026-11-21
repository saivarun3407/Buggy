# Findings: from a lead to a proven, graded, reported issue

A claim is not a finding. Everything an agent, a scanner or a probe reports
starts as a **candidate**; only an independent re-proof makes it a finding.
This page describes that path and the tools around it. All of it is plain
code: the model chooses what to test and judges results, nothing else.

## The path

| Step | Who does it | What happens |
|---|---|---|
| 1. Leads are queued | code | After recon, `hunt` queues scanner hits and ranked recon leads. A positive `probe_run` and every access-control mismatch from `authz_matrix_run` are queued automatically. Duplicates merge into one row. |
| 1b. Read-only probes run | code | `hunt` then runs the probe sweep (below): no model, nothing state-changing. What it finds is re-proven and graded in the same step. |
| 2. An agent picks a lead | agent | `candidates_next` returns the best unproven leads and claims them for that agent for a while. |
| 3. A claim is submitted | agent | `finding_submit` with assertions that cite capture ids. The submitter cannot set a status. |
| 4. The claim is re-proven | code | `finding_verify`. Only this sets `exploit_verified`. |
| 5. It is graded | code | `finding_grade`: `submit`, `hold` or `discard`, with the rule that fired. |
| 6. It is reported | code | `report_build` and the files `hunt` writes. Only verified findings are listed as findings. |
| 7. A fix is retested | operator | `buggy-cli retest` re-runs the same proof. |

Statuses: `candidate`, `exploit_verified`, `source_verified` (operator-recorded
code review), `inconclusive`, `discarded`. Grades: `submit`, `hold`, `discard`.

## The automatic probe sweep

After recon, `hunt` plans probe runs from the recon records by fixed rules and
sends each one through the evidence gateway (scope, rate limit and ledger
apply). It needs no model key.

| Input found by recon | Probes run |
|---|---|
| GET query parameter, file-like name (`file`, `path`, `page`, ...) | `path_traversal` |
| GET query parameter, URL-like name (`url`, `next`, `redirect`, ...) | `open_redirect` |
| GET query parameter, id-like or numeric | `sqli` (no time payloads) |
| any other GET query parameter | `sqli`, `xss_reflected`, `ssti` |
| each live service (10 at most) | `cors` |
| each GraphQL endpoint (5 at most) | `graphql_checks` |

- Never planned: request bodies, headers, cookies, path segments, any method
  but GET, any parameter that looks like a credential, and every probe that
  can change state or needs test accounts. Those stay with a run the operator
  approves.
- Budget: 40 probe runs by default (`--probe-budget N`; `--no-probes` or `0`
  turns the sweep off). Every host gets its first run of each probe before any
  host gets a second. One parameter name is probed on two URLs per host at most.
- A positive probe is queued, verified by running the probe again, and graded.
  `hunt` prints each one with its status and grade; `hunt-result.json` carries
  the counts under `probes`.
- `graphql_checks` sends its queries with POST. Where the engagement requires
  approval the gateway holds that request like any POST; `hunt` says how many
  checks are waiting, and one approval of that fixed request lets the next
  run through.
- The sweep tests what recon found. A parameter recon did not discover is not
  probed; `recon_coverage` and the report's leads show what is left.
- The lite stack has no evidence gateway, so it does not run the sweep.

## How a finding is verified

- **A finding that came from a probe** is verified by running that probe
  again. A probe has its own baseline, control and proof, so a fresh
  `vulnerable: true` is the proof. Anything else leaves it `inconclusive`. A
  target that was fixed is therefore never reported as verified, even when the
  endpoint still answers 200.
- **A finding an agent claimed** is verified by re-sending each cited capture
  and checking the assertions (`status`, `body_contains`,
  `body_not_contains`, `same_as`, `differs_from`). `same_as` / `differs_from`
  compare JSON by value, so two users' own records are not "the same".
- At least one cited capture must be on the endpoint the finding names.
  Evidence from another endpoint proves nothing about this one.
- A capture that can change state is not re-sent by the verifier; the finding
  stays `inconclusive` ("needs operator-approved replay").
- A cited capture that does not exist in this engagement, or is out of scope
  now, discards the finding.

## Grading rules, in order

1. not `exploit_verified` -> `hold` (`discarded` -> `discard`)
2. endpoint out of scope now -> `discard`
3. class excluded by the program, or a banned technique (denial of service,
   social engineering, physical) -> `discard`
4. remediation missing, shorter than 30 characters or a placeholder -> `hold`
5. duplicate of a finding already graded `submit` -> `discard`; same class and
   endpoint as a scanner-known issue -> `hold`
6. severity above the program's cap for the host -> capped, with the reason
7. severity `info`, or a low misconfiguration -> `hold`
8. otherwise -> `submit`

Every reason names its rule. A grade can go stale: re-grade after a new
verification. Reports and gates require `exploit_verified` **and** `submit`.

## Test accounts (identities)

Access-control bugs are found by asking the same question as two users. The
operator declares the accounts once, in
`~/.buggy/secrets/<engagement>/identities.json`:

```json
{
  "identities": [
    {
      "name": "alice",
      "role": "user",
      "owner_of": ["https://app.example.com/api/orders/1001"],
      "login": {
        "request": {
          "method": "POST",
          "url": "https://app.example.com/api/login",
          "headers": {"Content-Type": "application/json"},
          "body": "{\"email\": \"alice@example.com\", \"password\": \"{password}\"}"
        },
        "credentials": {"password": "..."},
        "extract": [{"name": "token", "from": "json", "path": "token"}],
        "apply": {"headers": {"Authorization": "Bearer {token}"}},
        "success": {"status": 200}
      }
    },
    {"name": "bob", "role": "user", "static": {"headers": {"X-Api-Token": "..."}}}
  ]
}
```

- Only the evidence gateway mounts that folder, read-only. The agent runtime,
  the sandbox and the scanners never see it.
- The gateway performs the login (scope-checked, rate-limited, recorded) and
  attaches the session when a request names `identity="alice"`. `{totp}` is
  filled from `credentials.totp_secret` (RFC 6238).
- An agent sees names, roles and owned objects (`identities_list`), never a
  password, token or cookie. Login bodies, and their hashes, are redacted in
  every agent view and in the ledger.
- An approval covers one request **as one identity**.

`authz_matrix_run` requests each URL (GET/HEAD only) as every identity and as
nobody, and reports per URL: `enforced`, `broken_access`, `public` or
`inconclusive`. No object ids are guessed; the caller supplies the URLs.

## Evidence, reports and CI

- `evidence_export` writes a redacted bundle under
  `~/.buggy/audit/<engagement>/evidence/<id>/`: `evidence.har`,
  `reproduce.sh` (curl commands), `captures.json`, `ledger-excerpt.jsonl`,
  `MANIFEST.json` with hashes. The agent gets the script and manifest back,
  not the ledger lines.
- `hunt` writes next to `recon-report.md` in `~/.buggy/control/<engagement>/`:
  `report.md`, `report.html` (self-contained, no script), `report.json`,
  `findings.sarif`, `hunt-result.json`.
- `buggy-cli ci-gate --report report.json --hunt-result hunt-result.json
  --fail-on high --sarif out.sarif` exits 0 / 10 / 3 / 2. See [ci.md](ci.md).

## Retest

```bash
docker compose --profile operator run --rm operator buggy-cli retest <engagement> --all-verified
```

Per finding: `still_vulnerable`, `fixed` or `inconclusive`. `fixed` needs two
consistent attempts and, for a finding with more than one assertion, a control
that still passes, so an outage or an expired login cannot look like a fix.
Exit 0 all fixed, 10 any still vulnerable, 3 any inconclusive.

## Lessons and the shared board

- `memory_save` / `memory_search`: reusable techniques across engagements.
  Secrets and target names are removed before storage. A lesson is trusted
  only when it cites a finding the verifier proved in that engagement;
  untrusted lessons are not returned by default.
- `fact_add`, `facts_list`, `intent_open`, `intent_claim`, `intent_conclude`,
  `hints_list`, `hint_add`: agents coordinate through an append-only board. A
  live claim by another agent is refused, so two agents do not do the same
  work.

## Guards on the agents

- **Tool-call guard.** Operator rules in the scope document
  (`machine_enforcement.tool_guard`: a regex, or `{pattern, name, tools,
  message}`) are checked against every argument of every gated tool call,
  after URL, HTML-entity, unicode-escape and base64 decoding and inside nested
  JSON. A bad rule rejects the scope at load. Try a call without running it:
  `buggy-cli scope test-call <engagement> --tool http_send --args '{...}'`.
- **Loop guard.** An agent that repeats one call three times, or makes eight
  near-identical calls, has the next one withheld with an explanation. Each
  role has a tool-call cap per run (`BUGGY_MAX_TOOL_CALLS`, default 300).
  Counts are written to `~/.buggy/audit/<engagement>/run-telemetry.jsonl`.

## Notifications

Set a webhook in `.env` and Buggy tells you when an approval is waiting, a
finding is verified, recon finished or a run failed:

```
BUGGY_NOTIFY_WEBHOOK_URL=
BUGGY_NOTIFY_SLACK_WEBHOOK_URL=
BUGGY_NOTIFY_DISCORD_WEBHOOK_URL=
```

A message never contains a request body, a credential or agent-written text.
Approving still happens with `buggy-cli approvals allow` or in the dashboard.

## Limits you should know

- **State-changing probes need one approval per run.** A probe that can
  change state (`command_injection`, `ssrf_canary`, `numeric_boundary`,
  `mass_assignment`, and any probe sent with POST/PUT/PATCH/DELETE) is held
  as a whole where the engagement requires approvals: `probe_run` returns
  `APPROVAL_REQUIRED` with a request id and sends nothing. The request shows
  the probe, the URL, the parameter, what the probe sends and its request cap
  (header names only, never values). After `buggy-cli approvals allow
  <engagement> <id>`, the same `probe_run` call runs once; its requests are
  recorded under that approval. One approval is one run of at most 40
  requests to the approved origin; verifying such a finding re-runs the probe
  and needs its own approval.
- **Lab coverage is partial.** See
  [benchmark/lab/results/coverage.md](../benchmark/lab/results/coverage.md):
  each known lab bug is listed as proven, pipeline-only, backlog or excluded.
  Reflected XSS, template injection, path traversal and CORS have no positive
  case in the lab apps; those probes are proven on unit fixtures only.
- **No agent run has been measured.** The agent stage needs a model key; the
  benchmark contract in `benchmark/RESULTS_POLICY.md` is ready, the results
  are not.
- Scanner hits with no recognisable class are not queued; `hunt` prints how
  many were left out.
