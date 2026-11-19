---
name: access-control-idor
description: Hunt broken access control — IDOR/BOLA on object identifiers, function-level authorisation (BFLA) on admin and role-gated routes, and tenant isolation. Prove it with two test accounts and a recorded cross-account read or write.
metadata:
  subdomain: web-exploitation
  when_to_use: "access control idor bola bfla broken object level authorization function level privilege escalation horizontal vertical tenant isolation object id uuid enumeration admin route forced browsing"
  mitre_attack: T1190, T1078
---

# Access Control / IDOR Playbook

Broken access control is decided by one question: *does the server check that
this caller may touch this object?* The deliverable is a recorded request in
which account B (or no account) reads or changes something that belongs to
account A.
## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`api_operation`, `endpoint`, `url` (paths with ids: `/users/{id}`, `/orders/123`, `?account=`)). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `idor`** — params `url` (an object that belongs to the owner),
`owner_headers`, `attacker_headers` (a different test account), optional
`markers` (strings unique to the owner's data), `check_unauthenticated`
(default true). It reads the object as the owner, then as the attacker, then
with no credentials, and reports `true` only when the attacker's response
carries the owner's data. An attacker identity the server rejects outright
gives `null`, not a pass. Not state-changing.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_idor_probe_finds_basket_idor` finds Juice Shop's
basket IDOR; `::test_idor_probe_does_not_flag_a_rejected_identity` is the negative control;
DVGA's private pastes are found by `::test_graphql_probe_finds_introspection_suggestions_and_private_data`.

## 1. Build the access matrix

Two test accounts per role, both yours. From `recon_query` list every
operation that takes an object identifier or is role-gated. For each, write
the expected rule (owner only / same tenant / admin only).

## 2. Lane A — Object level (IDOR / BOLA)

- Run `idor` on every object URL, with the owner's and the other account's
  headers. Feed it markers (email, order number) so a 200 with someone
  else's empty object is not counted.
- Identifier sources: sequential ids, ids leaked in other responses, ids in
  `js_file` records, GraphQL node ids.
- Writes: only after the read is proven and with approval — change one field
  on your own second account, never on a real user.

## 3. Lane B — Function level (BFLA)

- Call admin/role-gated operations with a low-privilege token via
  `http_send`. Try method swaps (GET ↔ POST) and versioned siblings
  (`/v1/` vs `/v2/`).
- A 403 that still performs the action is a finding; verify by reading back.

## 4. Lane C — Tenant isolation

- Swap tenant/org identifiers in path, header, and body. Check exports,
  search, and bulk endpoints — they often skip the per-object check.

## 5. Proof & report

One capture as the owner, one as the attacker showing the owner's data,
`capture_verify` on both. Remediation: enforce the ownership check
server-side on every object access, derived from the session, not from a
client-supplied identifier. `bounty_scope_check`, then the report tools.
