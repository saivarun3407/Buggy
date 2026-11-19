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
| 6 | `apispec` | OpenAPI / Swagger probing, GraphQL introspection | yes |
| 7 | `issues` | nuclei (vetted set), gitleaks on fetched JS and listed public repos | nuclei only |

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
