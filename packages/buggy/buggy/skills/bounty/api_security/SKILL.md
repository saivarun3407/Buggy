---
name: api-security-top10
description: Hunt the OWASP API Security Top 10 (2023) — BOLA/IDOR (API1), broken function-level authorization (API5), mass assignment and excessive data exposure (API3/API6), and resource/inventory abuse (API4/API9). Two-identity authZ testing against the live API surface.
metadata:
  subdomain: web-exploitation
  when_to_use: "api security owasp api top 10 bola idor object level authorization bfla function level mass assignment excessive data exposure rest openapi swagger postman two account cross tenant"
  mitre_attack: T1190
---

# OWASP API Security Top 10 Playbook

Modern bounties live in APIs because authorization is business logic and
scanners can't reason about it. The single most important habit:
**always test with two accounts.**

## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`api_spec`, `api_operation`, `endpoint`). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `mass_assignment`** — params `url`, `method`, a valid JSON `body`,
`extra_fields` (fields the client must not control, e.g. `{"role":"admin"}`),
optional `readback_url`, `headers`. Reports `true` only when the privileged
value is read back from the server. State-changing.

**Probe `idor`** — for object-level authorisation (BOLA) on every
`api_operation` with an id in the path: params `url`, `owner_headers`,
`attacker_headers`, optional `markers`.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_mass_assignment_probe_finds_admin_registration`
finds Juice Shop's admin registration; `::test_mass_assignment_probe_does_not_flag_an_ignored_field`
is the negative control.

## 1. Build the API surface

- Pull specs when available: OpenAPI/Swagger (`/openapi.json`,
  `/swagger.json`, `/v3/api-docs`), GraphQL introspection, Postman
  collections in `/workspace`.
- Otherwise observe traffic and fuzz the path/verb space
  (`ffuf`/`feroxbuster`), discover params with `arjun`.
- For each endpoint record: object acted on, expected authorization,
  data returned.

## 2. Lane A — BOLA / IDOR (API1, the #1 bug)

1. Capture an authenticated request containing an object ID.
2. Replay it as a *second* identity; swap/increment IDs (numeric, UUID,
   hashids, base64-wrapped).
3. Cross-tenant read or write = finding. A single-account "it returned
   data" is **not** a finding.

## 3. Lane B — Broken function-level authZ (API5 / BFLA)

- Map role-gated endpoints (admin, internal, management).
- Call them as a low-priv user; flip verbs (`GET`→`PUT`/`DELETE`);
  strip or forge role claims/headers.

## 4. Lane C — Mass assignment & data exposure (API3 / API6)

- Mass assignment: add fields the client never sends (`role`,
  `is_admin`, `verified`, `balance`) and confirm they persist.
- Excessive data exposure: inspect raw JSON for fields the UI hides
  (tokens, internal IDs, PII) — the server over-returns, client filters.

## 5. Lane D — Resource & inventory (API4 / API9)

- Rate-limit / pagination abuse for resource exhaustion (measured, no
  real DoS).
- Probe old versions (`/v1` vs `/v2`), staging hosts, undocumented
  routes — improper inventory management.

## 6. Proof & report

Capture the request/response pair that demonstrates the broken control.
`bounty_scope_check` the asset and vuln class, then `report_hackerone` /
`report_bugcrowd_csv`. Use `h1_search` for disclosed API chains and
`payload_search` for class payloads.
