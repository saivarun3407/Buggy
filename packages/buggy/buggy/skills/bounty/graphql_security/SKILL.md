---
name: graphql-security
description: Hunt GraphQL-specific bugs — introspection-driven schema recovery, resolver-level authorization gaps and IDOR via node/edges, alias/batching rate-limit amplification, and complexity/depth DoS. Targets /graphql and GraphQL-over-GET endpoints.
metadata:
  subdomain: web-exploitation
  when_to_use: "graphql introspection schema resolver authorization idor node edges alias batching amplification rate limit bypass complexity depth dos apollo hasura graphene mutation"
  mitre_attack: T1190
---

# GraphQL Security Playbook

GraphQL collapses an entire API behind one endpoint; its flexibility is
its attack surface. Find the endpoint (`/graphql`, `/api/graphql`,
`/v1/graphql`, GraphQL-over-GET), fingerprint the engine, then attack
the recovered schema.

## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`graphql` (introspection result, type and field names), `endpoint`). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `graphql_checks`** — params `url`, optional `headers`,
`unauthenticated_query` (a query that should need credentials) and `markers`
(strings that identify sensitive data in its result). Reports introspection,
field suggestions and data returned without credentials, each with its own
capture. Not state-changing. Never run batching/depth "DoS" checks against a
program.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_graphql_probe_finds_introspection_suggestions_and_private_data`
finds all three on DVGA; `::test_graphql_probe_does_not_flag_a_rest_endpoint` is the negative
control.

## 1. Discover & fingerprint

- Locate endpoint(s); fingerprint engine with `graphw00f` (Apollo,
  Hasura, graphene, etc.) — engine dictates which bypasses apply.

## 2. Lane A — Introspection & schema recovery

- Run the introspection query. If disabled, recover the schema via
  field-suggestion errors and known-type probing (`clairvoyance`).
- Introspection-on alone is at most info/low — its value is as a **map**
  to a real bug. Report the impactful bug; cite introspection as the
  enabler.

## 3. Lane B — Resolver authZ / IDOR

Authorization is per-resolver and frequently inconsistent across paths.

- Access objects via `node(id:)`, edges, and nested relations across two
  identities.
- Find fields exposed through one query path but guarded on another.

## 4. Lane C — Batching / alias amplification

- Alias-stack or array-batch sensitive mutations (login, OTP verify,
  promo redeem) to bypass per-request rate limits — turns one HTTP
  request into thousands of operations.

## 5. Lane D — Complexity / injection

- Deeply nested / cyclic queries for complexity/depth DoS — keep it
  **measured and in-scope**; do not actually take the target down.
- Test resolver arguments for SQL/NoSQL injection and SSRF sinks.

## 6. Mutations are the dangerous verbs

Enumerate every mutation and test authZ + mass-assignment on each — they
change state.

## 7. Proof & report

Capture the query/response proving impact. `bounty_scope_check`, then
`report_hackerone` / `report_bugcrowd_csv`. `payload_search` for GraphQL
payloads.
