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

## The automatic access-control check

When test accounts are declared (see *Test accounts* below) and at least one
lists an object it owns (`owner_of`), `hunt` asks for every owned object as
its owner, as every other account and with no credentials, and compares who
received whose data. Only GET requests are sent; logins go through the
gateway. An object a non-owner could read is queued, re-proven and graded
like any other finding. No model is involved.

Without declared accounts nothing is sent, and `hunt` says so:

```
access control   not run: no test accounts are declared; add two in ~/.buggy/secrets/<engagement>/identities.json
```

At the end of every run `hunt` lists what was **not tested** and the one thing
that enables each (accounts, a model, your approval). The same list is in
`hunt-result.json` under `not_tested`. A run that only shows scanner results
is a run where those things were missing.

## What `hunt` does once test accounts are declared

With accounts in `~/.buggy/secrets/<engagement>/identities.json`, `hunt` adds
these steps after the probe sweep. None of them uses a model.

| Step | What happens |
|---|---|
| Signed-in crawl | For each account (three at most) the gateway signs in and walks the application with up to 120 GET requests. Links that could sign out or change something are never followed; forms are recorded, never submitted. |
| Signed-in probes | The inputs found there that recon had not seen are probed as that account with the read-only probes. Positives are re-proven as the same account and graded. |
| Write operations | Forms that post, and the write operations of the API description, become state-changing probe runs: a negative or zero business quantity, a privileged field the client should not set, injection in a body or form field, a shell probe on a field that names a host or command. Each run is handed to the gateway and **waits for your approval**; `hunt --resume` sends the ones you allowed. 15 runs at most per run (`--state-probe-budget`). |
| Owned objects | An object URL only one account reached is asked for as the other accounts. It is reported only when the owner's `markers` come back to a non-owner, so declare markers. |

`hunt` prints one block per step and lists, at the end, what was not tested
and why. Limits: the crawl reads HTML links, forms and URLs inside JSON, so a
single-page application that builds its requests in script shows it little;
there, declare `owner_of` objects and let the agent stage do the rest. Field
values for write operations come from the API description or the form, so an
operation that needs a specific valid body may be refused by the target
before the check means anything.

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
- **A finding that came from a recipe** (below) is verified by running the
  same recipe again, controls included, under the same rule as a probe.

## Checks the agent builds itself (recipes)

When no probe fits a lead, the agent describes the check as a **recipe**: a
JSON document with the requests to send, what to take from each response for
the next one, and how to decide. Buggy's code validates it and runs it.

**A recipe is data, not code.** There is no expression language, no loop and
no condition in it: only literal requests with `{{var}}` placeholders, fixed
extraction rules (`json` path, response `header`, `regex`, `status`) and fixed
comparisons. Nothing the agent writes is executed, and every step goes through
the evidence gateway like any other request, so scope, the internal-address
block, the approval hold, the rate limit and the ledger apply to each step.
Nothing can leave the gateway. The host of every step URL must be written
out: a placeholder before the path is refused when the recipe is checked.

Worked example: can a second account read the first account's order?

```json
{"name": "order-read-by-other", "class": "access_control",
 "title": "Another account can read an order it does not own",
 "endpoint": "https://shop.example.test/api/orders/{id}",
 "remediation": "Return an order only to the account that owns it; answer 403 otherwise.",
 "steps": [
   {"id": "create", "method": "POST", "url": "https://shop.example.test/api/orders",
    "identity": "alice", "body": {"item": "book-{{rand}}"},
    "expect": {"status": [200, 201]},
    "extract": {"order": {"from": "json", "path": "order.id"}}},
   {"id": "owner", "method": "GET", "url": "https://shop.example.test/api/orders/{{order}}", "identity": "alice"},
   {"id": "other", "method": "GET", "url": "https://shop.example.test/api/orders/{{order}}", "identity": "bob"},
   {"id": "nobody", "method": "GET", "url": "https://shop.example.test/api/orders/{{order}}", "identity": ""}],
 "verdict": {
   "vulnerable_if": [{"step": "other", "status": 200}, {"step": "other", "same_as": "owner"}],
   "control": [{"step": "owner", "status": 200}, {"step": "nobody", "status": [401, 403]}]}}
```

- Placeholders: a variable extracted by an **earlier** step, or `{{rand}}` (one
  8-character token per run) and `{{ts}}` (unix seconds). Pipes:
  `|urlencode`, `|b64`, `|b64url`, `|json`, `|lower`, `|upper`. An object body
  is filled in value by value and sent as JSON.
- Conditions: `status`, `body_contains`, `body_not_contains`, `same_as` /
  `differs_from` (another step; the verifier's thresholds), and `json` with
  `equals`, `gt` or `lt`.
- **A control is required.** A control is the step that shows the normal,
  expected behaviour (the owner reads the order; a request without
  credentials is refused), so a positive means more than "the page answered".
  A recipe without one is refused. The result is `vulnerable: true` only when
  every control and every `vulnerable_if` condition holds; `false` when the
  controls hold and a `vulnerable_if` does not; `null` when a control fails
  (`control_failed`), a step got no answer (`not_sent`), or a step's `expect`
  failed (`precondition_failed`, which is never a finding).
- **Approval.** A recipe with any POST, PUT, PATCH or DELETE step can change
  state (the agent may also declare `"state_changing": true` on a GET-only
  one). Where the engagement requires approval it is held and approved as
  **one run**, like a state-changing probe: the operator sees the recipe name,
  each step's method and URL template, the accounts used and a body preview
  (header names only). One approval covers one run of that exact recipe, at
  most its step count plus two requests; an edited recipe needs a new one, and
  so does the verifier's re-run.
- Extracted values are never returned to the agent and never stored; results
  name only the variables.
- Tools: `recipe_check` (validate, sends nothing), `recipe_run` (a positive is
  queued as a candidate with source `recipe:<name>`), `recipe_save`,
  `recipe_list`, `recipe_get`; `recipe_run` with `{"use": "<name>"}` runs a
  saved recipe. Limits: 12 steps, 20 conditions, 64 KiB per body, regexes of
  200 characters at most.

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
      "markers": ["alice@example.com", "Alice Example", "ACC-100234"],
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

`markers` lists 1-20 strings, 3-200 characters each, that appear only in that
account's private data: its email address, its display name, an account
number. Two identities may not share a marker, and shorter strings are
refused because they would match by accident. The matrix looks for the
owner's markers in every response; a non-owner response that contains one is
the owner's data even when the page looks different. Markers are not shown
by `identities_list`.

An owner can be declared (`owner_of`, or the URL-to-identity map passed to
the matrix) or inferred. `owners_infer` takes the URLs each identity reached
while signed in, for example from a signed-in crawl, and gives an object URL
(an identifier after a named collection such as `/orders/1001`, or an id-like
query parameter such as `?order_id=1001`) to the one identity that reached
it. A URL that two or more identities reached is shared and gets no owner.
At most 60 owners are returned, with every identity and every path template
covered before any template gets a second URL. The result also names the
identities that declare no markers.

Being reached by one account only is a hint of ownership, not proof: a public
page that only one account happened to crawl looks the same. The URLs whose
owner was inferred are passed to `authz_matrix_run` as `inferred_json`. For
those, `broken_access` requires one of the owner's markers in the owner's own
response and in the response that should not have it. If the owner declares
no markers, or its own response contains none, the verdict is `inconclusive`
and nothing is queued. A declared owner is judged as before.

## Testing as a signed-in account

Most of an application sits behind its login. Two tools reach it as a declared
test account, without the agent ever holding the account's credentials.

**Probes.** `probe_run` accepts a top-level `"identity": "<name>"` in
`params_json`. Every request of the run is then sent as that account: the
gateway attaches its session, logging in first if needed. The result and its
captures name the identity. A positive result is queued with the identity on
every assertion, and the recorded run keeps it, so `finding_verify` re-runs the
probe, or replays the captures, as the same account. The identity is part of
a state-changing run's approval: an approval for a run as `alice` does not
cover the same run as `bob`, or the run without an identity. An unknown name
is refused with `UNKNOWN_IDENTITY` before anything is sent or an approval is
filed. `idor` and `jwt_alg_none` refuse `identity`: they take each account's
credentials in their own parameters and compare them, and a run-wide account
would mix two sources of authentication. A probe's deliberate "without
credentials" request (in `idor` and `graphql_checks`) never carries the
identity.

**Surface crawl.** `surface_crawl(seeds_json, identity="", max_requests=120)`
maps what an account can reach. From the seed URLs it follows links
breadth-first, on the seeds' hosts only, to depth 3 and at most `max_requests`
requests (1 to 300). Every request is a `GET` through the gateway, so scope,
the rate limit and the ledger apply as to any other request. It reads links,
scripts and frames from HTML, and URLs and rooted paths from JSON. A redirect
to the same host counts as a link; redirects are never followed by the
gateway itself. Forms are recorded with their method, action, field names and
default values, and are never submitted; a password field's value is never
kept. At most five URLs are requested per path template (numeric, UUID and
24-hex segments count as one `{id}`), so a long listing cannot use up the
budget. Static assets (images, fonts, style sheets, scripts, media, archives)
are listed, not requested. The result lists the pages by capture id, every
same-host URL seen, the forms, and every URL skipped with the reason. It
returns no response bodies: read a page with `http_capture`.

**What the crawl never requests.** Applications do act on GETs. A crawler that
followed every link would sign itself out, or delete or change the data it is
looking at. So a URL whose path or query contains one of these words (any
case, as a whole word; a camelCase step counts as a word break) is skipped
and listed with the reason:

- `logout`, `log-out`, `logoff`, `signout`, `sign-out`: the session would end
  and the rest of the crawl would run signed out;
- `delete`, `remove`, `destroy`, `purge`, `drop`: data would be removed;
- `unsubscribe`, `deactivate`, `disable`, `cancel`, `revoke`, `reset`: the
  state of an account, a subscription or a credential would change;
- `export`, `download`: a job or bulk transfer would start that the program
  did not ask for.

The list is `NEVER_REQUEST_WORDS` in `buggy/capture/crawl.py`. A refusal for
one URL (out of scope, internal address) is listed and the crawl goes on; a
refusal that would repeat for every request (no enforced scope, a failed
login) stops it, with `truncated: true`.

## Accounts Buggy creates itself

**When Buggy needs you.** Buggy registers and signs in by itself wherever it
can. Where a person is needed it stops that step, prints `YOUR TURN` with the
exact thing to do (and sends it to your notification webhook), and carries on
when you run `buggy hunt --resume <engagement>`:

| Blocker | What you do | What Buggy does on resume |
|---|---|---|
| CAPTCHA, a field it does not understand, a refused registration | Open the sign-up page and register the accounts with the email, user name and password Buggy prepared. They are in `~/.buggy/audit/<engagement>/accounts-created.json`. | Signs in with those values. |
| Email verification | Click the links in the emails sent to your address pattern. | Signs in. |
| No sign-up found, but a sign-in exists | Register the prepared accounts wherever the site lets you. | Signs in with them. |
| Single sign-on, or no sign-in Buggy can use | Sign in yourself and declare the accounts by session cookie or header in `identities.json` (see *Test accounts* above). | Uses the sessions you declared. |

Buggy never registers the same account twice, and a prepared account that
does not sign in yet is reported as waiting for you, not as a failure.

Access-control testing needs more than one account, and declaring them by hand
(the section above) is not always possible. When the operator allows it, Buggy
registers its own test accounts on the target, signs in and keeps the sessions
inside the gateway, exactly as it does for declared identities.

Registering an account changes the target, so it is a state-changing action and
is off by default. It is turned on only in the operator-written scope document,
with a block under `machine_enforcement`:

```json
"account_creation": {
  "enabled": true,
  "email_template": "qa+{tag}@yourcompany.example",
  "max_accounts": 2
}
```

The `hunt` command will write this block from a flag; it can also be added to
`control/<engagement>/roe.json` by hand. `email_template` must contain `{tag}`
and look like an email address; Buggy replaces `{tag}` with a random string so
each account gets its own address. `max_accounts` is 1 to 3 (default 2). The
written switch is the approval: it covers only the registration and login
requests of the accounts Buggy creates, and each such request is recorded as an
account-creation request (`approval_id = "account_creation"`), with its body and
the body's hash redacted everywhere because it holds a password.

**Use addresses you own.** Every account's email comes from your template, so
the template must point at a mailbox or domain the operator controls. The
accounts are real accounts on the target; a confirmation link or a later notice
goes to that address.

Buggy finds the sign-up deterministically, from an anonymous crawl of the seed
URLs (and any recon API operations): a form with a password field and an email
or username field whose action, page or button says register / sign up / join /
create account, or a JSON API whose path names users/register/signup/accounts.
It generates a strong password with `secrets` for each account, registers it,
signs in, and builds a working `static` identity from the session (a session
cookie, or a bearer token from the login response). The accounts are named
`auto1`, `auto2`, … and appear in `identities_list` with role `auto`; their
email and username become the account's markers automatically, so the
access-control matrix can tell their data apart. No password, email, cookie or
token is ever returned to an agent or written to the ledger.

**What stops it, with a named reason, rather than guessing:** a CAPTCHA on the
sign-up page (`CAPTCHA`), a page offering only single sign-on with no password
field (`SSO_ONLY`), a required field whose purpose Buggy cannot determine
(`UNKNOWN_REQUIRED_FIELD`), a sign-up that demands email verification before the
account works (`EMAIL_VERIFICATION`), no sign-up found at all (`NO_SIGNUP_FOUND`),
a registration the target refused (`REGISTRATION_REFUSED`), a session that could
not be obtained or verified (`LOGIN_FAILED`), or the switch being off
(`NOT_ENABLED`). Provisioning is idempotent: an account that already exists and
still signs in is reused, and only the missing ones are created.

**Where the accounts are.** The gateway writes the accounts it created, with
their passwords, to two files no agent can read: `data/accounts/<engagement>.json`
and a copy for the operator at `audit/<engagement>/accounts-created.json`, both
mode `0600`. These are **test data on the target.** When the engagement is done,
the operator should sign in with those credentials and delete the accounts (or
have the target's owner remove them).

## Evidence, reports and CI

**Evidence is for valid bugs only.** The evidence step runs only for a finding
that was re-proven and graded `submit`. A finding that was proven but held by
the grader (a duplicate of a known issue, outside the program's rules, no
real impact) gets no video and no log bundle; the reports list it as "proven,
not reportable" with the grader's reason. With no valid bug, no evidence is
recorded and the run says so.

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

### Proof video and screenshot

Each proven finding can get a short video and two screenshots, made from what
the evidence gateway recorded when the finding was proved.

- `buggy.findings.proof_page.proof_html(finding, engagement=..., generated_at=...)`
  turns one finding of the report into a single HTML page. The page opens with a
  title card that gives the ID, title, severity, class, endpoint and parameter,
  and says that nothing is sent to the target while the page is recorded. One
  section follows per proof step. Each section shows the request (method, URL,
  headers with credentials already redacted, and body) with the payload
  highlighted. It also shows the response status and body with the proving text
  highlighted, plus the capture IDs and SHA-256 hashes. Everything that came
  from the target is shown as escaped text. A stored XSS payload is displayed
  and never runs. The page has no script and loads nothing from outside. When a
  body is long, the page shows only the part around the proving text and marks
  each cut as `[… N bytes not shown …]`.
- The scoped browser's `proof_record(engagement, finding_id, html)` tool
  records that page. It opens a fresh browser context with JavaScript off and
  every network request blocked. It then shows the title card and scrolls
  through up to 8 steps, which takes under 30 seconds. It writes these files
  to `~/.buggy/audit/<engagement>/evidence/<finding-id>/`:
  `proof.webm` (the video), `proof.png` (the first proof step) and
  `proof-full.png` (the whole page). Running it again overwrites them.
- The video is **not** a new attack. It shows the exchange the gateway
  recorded during the re-proof. Re-running the attack live would hit the
  target again, and a proof that changed state could not be shown that way.
  Nothing reaches the target while the video is recorded.

### Word report

`buggy.findings.report.to_docx(report, images=..., videos=...)` (from
`buggy.findings.docx`) turns the report dict into a `.docx` file. It has no
dependencies outside the standard library, and the same input gives the same
bytes. The report contains:

- the title, the engagement, when the report was generated, the scope, and
  whether testing is complete;
- a summary with counts by severity and a table of the findings;
- a bug-class coverage table, when the report includes `coverage`;
- one section per proven finding, most severe first:
  - the severity and why. The reason is built from a fixed rule for the
    finding's class, the parameter, and whether the proof was sent without
    credentials or as a test account;
  - the CWE, the endpoint, the method, the parameter, and which account the
    finding was proven as;
  - each payload, with the request it was sent in;
  - numbered steps to reproduce, with curl commands;
  - what the target answered;
  - the evidence: capture IDs with SHA-256, the evidence folder and
    `reproduce.sh`;
  - the screenshot, embedded when `images[finding_id]` (PNG bytes) is given;
  - the name of the proof video, when `videos[finding_id]` is given;
  - the remediation and the retest status;
- a separate "Not proven" table for inconclusive, source-verified and
  candidate items;
- "Not tested, and why", when the report includes `not_tested`.

Text from the target is XML-escaped. Characters that XML cannot hold, such as
a NUL in a response, are removed, so they cannot corrupt the file.

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
- **The whole chain has been run once, on two practice apps.** On 2026-11-22
  one `hunt` command with no model ran recon, the class-by-class tests, proof
  recording and the Word report against a local Juice Shop and DVWA in 12
  minutes 18 seconds: eight issues proven (five injection, one XSS, one file
  inclusion, one open redirect), eight videos, eight log bundles, one
  `report.docx`. Account creation was allowed and did not work there: Juice
  Shop is a single-page application whose sign-up is built in script, so no
  registration form or described API was found, and DVWA has no sign-up; the
  DVWA accounts were declared by hand. Self-created accounts are proven by
  unit tests only.
- **Signed-in testing has been run on one practice app.** On 2026-11-21
  `hunt` ran against a local DVWA with two declared accounts and no model:
  5 minutes 37 seconds, 74 URLs reached behind the login, and six issues
  found, re-proven and graded: file inclusion, SQL injection (two pages and a
  login form), reflected XSS and command injection. The same run without
  accounts found none of them. It has not been run on a real program, and a
  single-page application gives the crawl much less to read.
- **Web and API recon has been run on one practice app.** On 2026-11-22 the
  recon pipeline ran on the local Juice Shop and DVGA with the issue scan
  turned off: 84 seconds. The two new stages sent 6 known-file requests,
  4 discovery requests and 40 endpoint GETs. They found 14 sign-in related
  pages, 3 API roots, security.txt and the missing headers, and one
  endpoint that hands out `User.email`, `User.password`, `User.role`,
  `User.deluxeToken` and `User.totpSecret` with no login (`/rest/memories`).
  Before this, only the agent had found that endpoint. Nothing has been run
  on a real program.
- **Two agent runs have been measured, both on the practice apps.** Claude
  Code ran the agent stage through the agent bridge
  ([claude-code-agent.md](claude-code-agent.md)).
  - 2026-11-21, capped at 45 tool calls: 115 seconds, the two findings of the
    probe sweep confirmed, one held request left for the operator, and eight
    further observations it captured but did not submit before the cap.
  - 2026-11-22, capped at 120 tool calls (it stopped at 99): 255 seconds. With
    the 8 findings of the code stages the run ended at 23 proven findings, 20
    graded valid and 3 held by the grader as scanner duplicates. Seven of the
    23 came from checks the agent built itself as recipes (among them a login
    bypass, a forged-token login, reading another user's basket, a password
    change without the current password, and an order with a negative
    quantity). Finalizing took 233 seconds and wrote 20 videos, 20 log
    bundles and the Word report; the 3 held findings got no evidence. No web
    page fetch was recorded in this run, so `research_fetch` is covered by
    unit tests only.
  - Side effects of the second run, on the practice app: about 14 throwaway
    accounts registered (two with an admin role) and two basket items with a
    negative quantity. Lab mode has approvals off. On a real program each of
    those requests is held for your approval first.
  - Account creation printed the "your turn" message on these apps (one has
    no sign-up, the other's sign-up is drawn by JavaScript); creating accounts
    end to end is covered by unit tests only.

  Nothing has been measured on a real program, and Buggy's built-in agents
  (which need a model key) have not been run; the benchmark contract in
  `benchmark/RESULTS_POLICY.md` is ready, the results are not.
- Scanner hits with no recognisable class are not queued; `hunt` prints how
  many were left out.
