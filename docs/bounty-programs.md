# Running against a real bounty program

Only programs you name, only the scope the program publishes, enforce mode
only. Nothing in this document is automatic: an engagement against a real
program exists only after an operator runs `scope import` and confirms it.

## 1. Import the official scope

From the platform API (HackerOne `structured_scopes` + policy, or the Bugcrowd
program brief):

```bash
docker compose --profile operator run --rm operator buggy-cli scope import --platform hackerone --handle <program>
```

Without API access, download the scope CSV from the program's HackerOne page:

```bash
docker compose --profile operator run --rm operator buggy-cli scope import --platform hackerone --handle <program> --csv /control/<program>-scope.csv
```

API tokens (`H1_API_USERNAME`, `H1_API_TOKEN`, `BUGCROWD_API_USERNAME`,
`BUGCROWD_API_TOKEN`) are read from the operator's environment only. No agent
container has them.

The command prints what it will enforce and asks for confirmation:

- in scope / out of scope (assets not eligible for submission are out of scope)
- assets from the official data it **rejected** and why: wildcards over a
  public suffix, private or loopback ranges, networks larger than /16
- non-network assets (mobile apps, source code), which are ignored
- rate limit, pipeline mode, banned techniques

It writes two files under the operator-controlled root, which no agent-facing
container can write:

| File | Content |
|---|---|
| `control/<engagement>/roe.json` | enforced scope, `mode: enforce`, approvals required |
| `control/<engagement>/program.json` | source, source hash, rate limit, banned techniques, excluded classes |

Confirming the import authorises the recon pipeline: the worker starts a run
for a new or changed scope. Wildcards cover exactly one DNS label
(`*.example.com` matches `a.example.com`, not `a.b.example.com`).

## 2. What is enforced, and where

| Rule | Enforced by |
|---|---|
| Enforce mode only | Gated tools are refused with `PROGRAM_REQUIRES_ENFORCE` if a program engagement's scope is in any other mode; the pipeline and the evidence gateway only ever run in enforce mode; `scope set` refuses to loosen it |
| Scope | RoE guardrail, egress guard (network), pipeline scope filter, evidence gateway, scoped browser |
| Rate limit | Default 5 req/s; a limit stated in the program policy can only lower it; `--rps` is capped at 20. Applied to the pipeline, the gateway and gated tools |
| No DoS | Stress/flood tools are refused by the command parser; DoS findings are refused; nuclei runs medium+ severities and never runs templates tagged `dos`, `fuzz` or `intrusive` |
| No social engineering | Phishing/mail tooling is refused by the command parser; such findings are refused |
| No exfiltration beyond PoC | Stated to the agent as a program rule; every evidence request is recorded in full for review; reports need operator approval |
| Automated scanning forbidden by the program | Pipeline runs passive sources only; scanner commands are refused |
| Port scan | Off unless `--port-scan` is passed, and never when scanning is forbidden |

## 3. Human approval

Two things always wait for the operator on a program engagement.

**State-changing requests.** Any request through the evidence gateway that is
not GET/HEAD/OPTIONS is held. The approval covers that exact method, URL and
body, for at most three sends.

```bash
docker compose --profile operator run --rm operator buggy-cli approvals list <engagement>
```

```bash
docker compose --profile operator run --rm operator buggy-cli approvals allow <engagement> <request-id>
```

**Report release.** `report_hackerone` / `report_bugcrowd_csv` do not return
the report until the operator approves that exact text. The draft is written
to `audit/<engagement>/reports/<request-id>.md`; an edited report is a new
request. Buggy never submits to a platform itself: release means the report
text is handed back for you to submit.

An unanswered request is a refusal.

## 4. What a finding must contain

`report_record_finding` refuses a finding on a program engagement unless:

- `capture_ids` cites at least one request sent through the evidence gateway;
- each capture exists for this engagement, targets the cited host, and is in
  the enforced scope;
- each capture that cannot change state reproduces when re-sent (a
  state-changing capture is not re-sent automatically);
- `remediation` says what the owner should change (not a placeholder);
- the class is not one the program excludes, and not a banned technique.

A graph node without that evidence cannot be reported to the program,
whichever tool wrote it.

## 5. Limits you should know

- No real program has been run with this code. The import, gates and
  approvals are covered by tests with fixtures; the fixture uses the real
  HackerOne CSV header with synthetic rows.
- The API import paths (`fetch_official`) are exercised only up to the
  credential check; the HTTP calls reuse the existing intake code and were not
  run against the live APIs here.
- Policy text is parsed by keywords for "no automated scanning" and
  requests-per-second. Read the program page yourself and lower `--rps` or
  edit the imported scope if the policy says something the parser missed.
- The older in-process tools (`http_request`, `browser_action`, `proxy_*`)
  are scope-checked by the RoE parser but do not pass through the evidence
  gateway or its approval hold. Evidence must come from `http_send`,
  `probe_run` or the scoped browser.
