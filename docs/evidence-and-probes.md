# Evidence gateway, probes and the stack's MCP servers

Agents do not run scanners and do not send evidence requests themselves. They
query four services over MCP; each service is plain code with its own scope
check. The engagement is bound from the run and is never a tool argument the
model chooses.

| Service | Port | Code | Agent tools |
|---|---|---|---|
| `pipeline-mcp` | 9460 | `buggy/pipeline/mcp_server.py` | `recon_summary`, `recon_assets`, `recon_query`, `recon_record`, `recon_diff`, `recon_scope_drops`, `recon_coverage`, `recon_raw`, `recon_request_rerun`, `recon_rerun_status` |
| `capture-mcp` | 9461 | `buggy/capture/mcp_server.py`, `buggy/capture/workbench.py` | `http_send`, `http_replay`, `http_capture`, `http_captures`, `capture_verify`, `probe_list`, `probe_run`, and the findings layer: `candidates_next`, `finding_submit`, `finding_verify`, `finding_get`, `findings_list`, `finding_grade`, `leads_ruled_out`, `findings_chains`, `findings_due`, `report_build`, `evidence_export`, `identities_list`, `authz_matrix_run`, `memory_search`, `memory_save`, `facts_list`, `fact_add`, `intent_open`, `intent_claim`, `intent_conclude`, `hints_list`, `hint_add` (see [findings.md](findings.md)) |
| `scope-mcp` | 9462 | `buggy/capture/scope_server.py` | `scope_show`, `scope_check`, `program_info` |
| `browser-mcp` | 9463 | `buggy/scoped_browser/mcp_server.py` | `browser_open`, `browser_click`, `browser_fill`, `browser_eval`, `browser_text`, `browser_html`, `browser_screenshot`, `browser_cookies`, `browser_requests`, `browser_close` |

Agent-side wrappers: `buggy/tools/stack_mcp.py`. Read-only roles get recon,
scope and the read-only findings, board and lessons tools; testing roles get
all four servers. The engagement and the acting agent's name are filled in
from the run: no tool lets the model choose either.

## Evidence gateway (`capture-mcp`)

Every `http_send` goes through, in order:

1. **Scope** — the URL's host must be in the enforced `roe.json`
   (`OUT_OF_SCOPE`, `NO_ENFORCED_SCOPE`).
2. **Internal addresses** — an in-scope name that resolves to a private,
   loopback or link-local address is refused (`INTERNAL_ADDRESS`) unless that
   address is itself in scope or the engagement sets
   `network.allow_private_targets` (labs, internal assessments).
3. **Approval** — any method other than GET/HEAD/OPTIONS is held until the
   operator allows that exact request as that identity (`APPROVAL_REQUIRED`),
   unless the engagement sets `approvals.state_changing: "not_required"`
   (labs only). The only exception is a login request the operator declared
   for a test account, which the gateway sends itself.
4. **Rate limit** — the engagement's `pipeline.rate_limit_rps`.
5. **Send** — redirects are returned, never followed.
6. **Record** — full request and response in the capture store, plus a
   hash-chained line in `audit/<engagement>/captures.jsonl`.

`http_replay` re-sends a capture; `capture_verify` re-sends it and reports
whether the result matches and whether the host is in scope. A finding's PoC
is a capture id that verifies.

## Probes

`probe_run` executes one deterministic check through the gateway and returns
`vulnerable: true | false | null`, a summary, the capture ids, and a
remediation. `null` means "could not tell" and is never reported as a pass.

| Probe | Class | Lab test that proves it |
|---|---|---|
| `jwt_alg_none` | auth / session | `test_jwt_probe_finds_unsigned_token_acceptance` |
| `idor` | access control | `test_idor_probe_finds_basket_idor` |
| `ssrf_canary` | SSRF | `test_ssrf_probe_finds_profile_image_ssrf` |
| `numeric_boundary` | business logic | `test_boundary_probe_finds_negative_quantity` |
| `mass_assignment` | API | `test_mass_assignment_probe_finds_admin_registration` |
| `graphql_checks` | GraphQL | `test_graphql_probe_finds_introspection_suggestions_and_private_data` |
| `sqli` | injection (CWE-89) | `test_sqli_probe_finds_product_search_injection`, `..._login_injection`, `..._graphql_filter_injection` |
| `command_injection` | injection (CWE-78) | `test_command_injection_probe_finds_import_paste`, `..._system_diagnostics` |
| `open_redirect` | open redirect (CWE-601) | `test_open_redirect_probe_finds_the_juice_shop_allowlist_bypass` |
| `xss_reflected` | XSS (CWE-79) | none: the lab apps have no server-side reflected sink (unit fixtures only) |
| `ssti` | injection (CWE-1336) | none in the lab (unit fixtures only) |
| `path_traversal` | file handling (CWE-22) | none in the lab (unit fixtures only) |
| `cors` | misconfiguration (CWE-942) | none in the lab (unit fixtures only) |

Tests live in `packages/buggy/tests/lab/` and run against real Juice Shop and
DVGA containers (`BUGGY_LAB=1`). Each probe also has a negative control. The
access-control matrix (`authz_matrix_run`) is proven by
`test_authz_matrix_lab.py`. What is and is not covered is audited in
`benchmark/lab/results/coverage.md`.

A positive probe result is queued as a candidate finding and is later
verified by running the same probe again (see [findings.md](findings.md)).

The SSRF probe needs a callback listener the target can reach:
`BUGGY_CANARY_BASE_URL` (a hostname you control that forwards to port 9470 of
`capture-mcp`). Without it the probe returns `null`.

## Scoped browser (`browser-mcp`)

Chromium with a route handler on every request: out-of-scope and
internal-address requests are aborted and listed in `browser_requests`. While
the engagement requires approval for state-changing requests, the browser
only lets GET/HEAD/OPTIONS through.

## Trust boundaries

- None of these services is on the sandbox network; the agent's shell cannot
  reach them. Only langgraph calls them.
- All mount the control root read-only. Only `capture-mcp` writes the capture
  store. `scope-mcp` has no network egress.
- None carries model credentials.

Invariants are pinned in `tests/test_compose_network_isolation.py`.

## Authentication

Every request to these four servers must carry
`Authorization: Bearer $BUGGY_STACK_MCP_TOKEN`. The token is generated by
`buggy onboard` / `scripts/ensure-stack-secrets.sh`, held by the servers and
langgraph, and never given to the sandbox. A server refuses to start without
it.

## Older in-process tools

`http_request`, `proxy_send_request`, `detect_tech_stack` and
`browser_action` used to open their own connections from the langgraph
process. When the stack's gateway and browser are deployed they are routed
there instead: same scope check, approval hold, rate limit and recording.
The langgraph process no longer connects to a target itself.

## Known limits

- The gateway and the pipeline each rate-limit their own requests. The recon
  run finishes before the agents start in `buggy hunt`, so they do not add
  up; an agent that requests a re-run while it is also testing can exceed
  the per-engagement rate by up to a factor of two.
- The pipeline enforces scope in its own code and scanner flags (no redirect
  following, crawler field scope); it is not behind the egress guard.
