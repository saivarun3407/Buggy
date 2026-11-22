# Deterministic recon pipeline

Anything a tool can do deterministically does not go to an agent. The
pipeline (`packages/buggy/buggy/pipeline`) runs the scanners as plain code,
normalises their output into one schema, and writes it to the recon store.
Agents read that data over MCP. There is no model call anywhere in the
pipeline; `test_guards.py::TestNoLLMInTheLoop` enforces it.

## Stages

| # | Stage | Tools | Touches the target |
|---|---|---|---|
| 1 | `enumerate` | subfinder, amass (`-passive`), crt.sh | no |
| 2 | `dns` | dnsx: A, AAAA, CNAME, MX, TXT, NS | no (public resolvers) |
| 3 | `live` | naabu (connect scan), httpx | yes |
| 4 | `fingerprint` | technology, TLS, response headers from the stage-3 probe | no new requests |
| 5 | `urls` | katana, gau, waybackurls, JS endpoint extraction | katana and JS fetch only |
| 6 | `web` | web recon: robots.txt, sitemaps, security.txt; security headers and session cookie flags; sign-in pages by kind | known files only |
| 7 | `apispec` | OpenAPI / Swagger probing, GraphQL introspection | yes |
| 8 | `api` | API recon: API roots and versions, OAuth / OpenID discovery, one unauthenticated GET per API endpoint | discovery documents and the endpoint GETs |
| 9 | `issues` | nuclei (vetted set), gitleaks on fetched JS and listed public repos | nuclei only |

## Web and API recon

Both stages are built in (no binary), read-only, rate-limited, and send every
request through the scoped client, so an out-of-scope URL in a sitemap or a
discovery document is never requested or stored.

**`web`** (`pipeline/tools/webrecon.py`), per live origin:

- fetches `/robots.txt`, `/sitemap.xml` (and up to five nested sitemaps or the
  sitemaps robots.txt names) and `/.well-known/security.txt`. Paths and
  sitemap URLs become `url` records, cut at the first wildcard, so the
  parameter extraction and the tests see them;
- reads the headers the live probe stored (no request) and records a missing
  `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options` (unless `frame-ancestors` is set) or, on HTTPS,
  `Strict-Transport-Security`; a session cookie without `Secure`, `HttpOnly`
  or `SameSite`; a `Server` or `X-Powered-By` value with a version number
  (`web_finding`). These go in the report's fix list, never in the lead queue;
- sorts every stored page and endpoint into sign-in, sign-up, password reset,
  logout, multi-factor, OAuth, account and admin pages (`auth_surface`).

**`api`** (`pipeline/tools/apirecon.py`), per live origin:

- groups every API-looking URL, endpoint and operation by its root
  (`/api/v2`, `/rest`), with the versions served side by side and how many
  endpoints take an object id in the path (`api_base`);
- fetches `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`; the endpoints they name become
  `auth_surface` records of kind `oauth`;
- sends one GET with no credentials to each concrete API endpoint, at most 40
  per origin, endpoints with an object id first. The query string is never
  sent (an archived URL can carry a reset token), templates such as
  `/users/{id}` are skipped, and so is any URL that names logout, delete or a
  switch (the crawler's rule). It keeps the status, whether it asked for
  credentials and how, the CORS and rate-limit headers, the methods a 405
  allows, and the top-level field names of a JSON answer, never the values
  (`api_profile`). A 404 or 410 is not kept.

With `passive_only` both stages send nothing and still do the parts that only
read the store.

What they add to the lead queue (`rank_candidates`):

| Record | Lead |
|---|---|
| `api_profile`: answered with no login, object id in the path | access control, `idor` |
| `api_profile`: answered with no login, a list or sensitive field names | information exposure |
| `api_profile`: `Access-Control-Allow-Origin` `*` or `null` with credentials | misconfiguration, `cors` |
| `api_profile`: asks for a bearer token | login and session, `jwt_alg_none` |
| `auth_surface`: password reset, MFA, OAuth, sign-in, sign-up | login and session |
| `auth_surface`: admin page | access control |
| `api_base`: more than one version served | API |
| `web_finding`: session cookie without its flags | misconfiguration |
| `js_file` source map | information exposure |

## Scope

The pipeline reads the **enforced** scope, `control/<engagement>/roe.json`
(see [scope-enforcement.md](security/scope-enforcement.md)), and refuses to
run unless it is in `enforce` mode with a non-empty `in_scope`.

- Every stage filters its **inputs** before a tool runs and its **outputs**
  before they are stored. A rejected candidate is written to the
  `scope_drops` table (stage, tool, direction, candidate, reason) and goes no
  further.
- Seeds come only from `in_scope`: `*.acme.com` becomes the enumeration root
  `acme.com`; a host or address is probed as-is; CIDRs above 1,024 addresses
  are skipped.
- httpx and nuclei do not follow redirects, and the built-in HTTP client
  checks every redirect hop, so a redirect cannot carry a request off-scope.
- The pipeline container is not behind the egress guard. Its scope control is
  this filter, in code, with the tests below.

## Program rules

Rate and technique limits come from the enforced `roe.json`:

```json
{
  "machine_enforcement": {
    "mode": "enforce",
    "in_scope": ["*.acme.com"],
    "min_inter_request_delay_ms": 200,
    "max_concurrent_connections": 5
  },
  "pipeline": {
    "rate_limit_rps": 10,
    "passive_only": false,
    "port_scan": true,
    "ports": "top-100",
    "crawl_depth": 2,
    "nuclei_severities": ["low", "medium", "high", "critical"],
    "disabled_stages": [],
    "public_repos": ["https://github.com/acme/app"]
  }
}
```

`min_inter_request_delay_ms` and `max_concurrent_connections` are ceilings: the
`pipeline` block can only go lower. They become `-rl` / `-rate` / `-c` / `-t`
on every active tool. `passive_only: true` (for programs that ban automated
scanning) runs stages 1–2 and the archive lookups and sends nothing to the
target.

## Schema and store

One record is one fact about one asset:

| Field | Meaning |
|---|---|
| `engagement` | engagement slug |
| `asset` | in-scope host or address the fact is about |
| `type` | `subdomain`, `dns_record`, `port`, `http_service`, `technology`, `tls`, `header`, `url`, `js_file`, `endpoint`, `api_spec`, `api_operation`, `graphql`, `vulnerability`, `secret` |
| `value` | the fact, canonicalised |
| `attrs` | structured detail |
| `source_tool`, `tool_version` | which tool, which pinned version |
| `first_seen`, `last_seen` | timestamps |
| `raw_ref` | `raw/<engagement>/<run>/<stage>-<tool>.out#L<n>`: the unparsed output line |

The store is SQLite (`recon.sqlite3` in the `pipeline_data` volume).

- **Dedupe**: identity is `(engagement, type, asset, value)`. Two tools
  reporting the same fact give one record and two rows in `observations`.
- **Cache**: each stage records the inputs it processed and a hash of the
  upstream facts they depended on. A re-run processes only inputs that are
  new, whose upstream facts changed, or that are older than `--max-age`
  (default 24 h).
- **Diff**: every run records what it added, changed and removed. A record is
  retired when the input that produced it was re-processed and no longer
  reports it, or when that input no longer exists.
- **Raw output**: kept on disk with its SHA-256, the tool's argv and version.
- Secrets are stored redacted (`gitleaks --redact`): rule, location and
  fingerprint, never the value.

## Pinned tools

`buggy/pipeline/versions.py` is the single source of truth.
`containers/pipeline.Dockerfile` installs exactly those versions and writes a
manifest of the binaries' SHA-256 hashes; at run time a binary whose hash is
not in the manifest is refused.

| Tool | Version |
|---|---|
| subfinder | 2.17.0 |
| amass | 4.2.0 |
| dnsx | 1.3.1 |
| httpx | 1.12.0 |
| naabu | 2.7.0 |
| katana | 1.8.0 |
| nuclei | 3.11.1 |
| nuclei-templates | v10.5.2 |
| gau | 2.2.4 |
| waybackurls | 0.1.0 |
| gitleaks | 8.30.1 |

The nuclei set is one pinned templates release, limited to
`http/{exposures,misconfiguration,exposed-panels,technologies,cves,vulnerabilities,takeovers}`
and `ssl`, with `dos`, `fuzz`, `intrusive`, `brute-force`, `default-login` and
`bypass` tags excluded, no DAST, code or headless templates, no OAST server
and no redirects.

## Running it

The `pipeline` service runs an engagement automatically when its scope is
first approved or changes. To run by hand:

```bash
docker compose run --rm pipeline run <engagement>
```

```bash
docker compose run --rm pipeline status <engagement>
```

```bash
docker compose run --rm pipeline diff <engagement>
```

```bash
docker compose run --rm pipeline drops <engagement>
```

```bash
docker compose run --rm pipeline tools
```

## What agents can do

`pipeline-mcp` serves the store read-only (the volume is mounted `:ro`):

| Tool | Purpose |
|---|---|
| `recon_summary` | counts by type, last run, diff |
| `recon_assets` | in-scope assets with record counts |
| `recon_query` | records by type / asset / substring, paged |
| `recon_record` | one record and all its observations |
| `recon_diff` | what a run added, changed, removed |
| `recon_scope_drops` | what was dropped as out of scope, and why |
| `recon_raw` | the raw output line behind a `raw_ref`, with argv and hash |
| `recon_request_rerun` | queue a re-run for **one** in-scope asset |
| `recon_rerun_status` | pending / completed / rejected / failed |

No tool runs a scanner or takes a flag, template or command. A re-run request
is reduced to a host name, checked against the enforced scope when it is
queued and again when the worker serves it.

## Tests

| Test | What it proves |
|---|---|
| `tests/unit/pipeline/test_parsers.py` | each parser against real output of the pinned version (`fixtures/README.md` lists how each file was captured) |
| `tests/unit/pipeline/test_scope_and_store.py` | scope decisions, limits, dedupe, diff, cache, read-only handle |
| `tests/unit/pipeline/test_pipeline_flow.py` | stage order; out-of-scope assets never reach a tool or the store; re-runs process only new or changed assets; program rules |
| `tests/unit/pipeline/test_guards.py` | no LLM imports; version pins; scoped HTTP; MCP surface; worker re-checks scope |
| `tests/test_compose_network_isolation.py` | the pipeline's network and the store's read-only mount |

## Running, progress and recovery

- The worker runs up to `BUGGY_PIPELINE_PARALLEL` (default 3) engagements
  side by side; each engagement has at most one run in flight.
- A running run records its current stage; `recon_summary` returns it as
  `current_run`, which is what `buggy hunt` prints.
- A run whose process died (restart, crash) is closed as `interrupted` at
  the next start and the engagement becomes due again. Finished stages are
  cached, so the resumed run only does what was left.
- `pipeline.seed_urls` (written by `buggy hunt` from the URLs you name)
  tells the live stage which non-default port to probe when the port scan
  is off and gives the crawler a starting path. Seeds are scope-filtered
  like every other input.
- The recon report (`buggy/pipeline/report.py`) is built by `buggy-cli hunt`
  from the read-only recon server and written to
  `control/<engagement>/recon-report.md`.


## Operator-supplied API contracts

The `apispec` stage only finds a specification the target publishes. When it
publishes none, hand the pipeline one: put an OpenAPI 3 / Swagger 2 file
(JSON or YAML) or a Postman v2.1 collection under
`control/<engagement>/contracts/` and name it in the enforced `roe.json`:

```json
{
  "pipeline": {
    "api_contracts": [
      {"path": "shop.openapi.yaml"},
      {"path": "accounts.postman.json", "base_url": "https://api.acme.com", "format": "postman"}
    ]
  }
}
```

| Key | Meaning |
|---|---|
| `path` | file below `contracts/`. An absolute path or one with `..` is rejected when the scope is loaded (the entry is left out, with a warning); the loader also refuses a link that leads out of the directory. At most 10 entries. |
| `base_url` | optional. Where the API is served, instead of the servers the file names. For a Postman collection it stands in for a leading `{{variable}}` the collection does not define, and otherwise replaces scheme, host and port of every request, so use it only for a collection that describes one API. |
| `format` | `openapi`, `postman` or `auto` (default). |

A contract is input data, read at the start of the `apispec` stage:

- **No request is made for it.** It adds records, not probes. It is read even
  with `passive_only`; a disabled `apispec` stage reads nothing.
- **Scope.** Every server and every operation URL it names goes through the
  scope filter as an input of the tool `contracts`. An out-of-scope server or
  request is dropped and listed by `pipeline drops` like any other. Also
  listed there, with their own reason: a Postman request whose URL has a
  variable the collection does not define (`UNRESOLVED_VARIABLE`) or one
  named like a credential, which is never substituted (`SECRET_VARIABLE`),
  and a server that is not an absolute http(s) URL (`NOT_ABSOLUTE_URL`).
- **Records.** One `api_spec` per in-scope host (value `contract:<path>`) and
  one `api_operation` per operation, in the shape discovery writes, with
  `source_tool` `contracts` and `attrs.source` `"operator"`. An operation the
  target's own spec also declares is the same record with both sources.
- **Names only.** A contract can hold credentials. Records carry header,
  query, form and body-property names (`attrs.parameters`,
  `attrs.request_body_properties`, `attrs.form`), never a header value, an
  auth block, a body or example value, a query value or URL userinfo. The raw
  output kept for a contract is the records, not the file.
- **Cache.** A contract is one input, keyed on the SHA-256 of its file. An
  unchanged file is hashed and not parsed again. Contracts are parsed again
  when a file changes, on `--force`, after `--max-age`, and whenever the
  stage re-probes an origin. One the scope no longer names is retired.
- **Parameters.** The stage's parameter extraction reads contract operations
  like discovered ones, for hosts with a live web service the stage processes
  in that run. An unreadable or malformed contract is reported under
  `stages.apispec.tools.contracts.errors` in the run and the run continues.

`tests/unit/pipeline/test_contracts.py` covers the three formats, the scope
drops, variable resolution, that no fixture credential reaches a record,
path rejection and the cache.
