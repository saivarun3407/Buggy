---
name: business-logic-race
description: Hunt business-logic flaws and race conditions — workflow/state-machine abuse, economic/quantity logic bugs, and TOCTOU/parallel-request races (double-spend, coupon reuse, limit overrun). The bugs scanners structurally cannot find.
metadata:
  subdomain: web-exploitation
  when_to_use: "business logic flaw race condition toctou parallel request double spend limit overrun coupon reuse workflow state machine multi step price tampering negative quantity quota bypass concurrency"
  mitre_attack: T1190
---

# Business-Logic & Race-Condition Playbook

These are flaws in what the app is *supposed* to allow — there is no
signature for "the discount stacked." Find them by understanding intent,
then violating it.

## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`api_operation`, `endpoint` (cart, order, transfer, coupon, quantity, amount)). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `numeric_boundary`** — params `url`, `method`, a valid JSON `body`,
`field` (dotted path of the numeric field), optional `values` (default
`[-1]`), `headers`. Reports `true` when the server accepts and stores a
negative or zero value. State-changing: use a test account's own cart/order,
and clean up after.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_boundary_probe_finds_negative_quantity` finds Juice
Shop's negative-quantity basket item; `::test_boundary_probe_does_not_flag_a_validated_field`
is the negative control.

## 1. Reconstruct intent

Map the workflow / state machine and its invariants: order of steps,
ownership, balance/quota, single-use constraints. Name each invariant
explicitly — that is what you will try to break.

## 2. Lane A — Workflow / state abuse

- **Step-skipping** — reach step N without completing N-1 (e.g. checkout
  without payment).
- **Out-of-order / replay** — replay a single-use action; reorder steps.
- **Trusted carried state** — tamper a value the server trusts from an
  earlier step (price, user ID, status baked into a hidden field/token).

## 3. Lane B — Race conditions (TOCTOU)

The bug is a timing window between check and use.

1. Identify limit-once operations: redeem, withdraw, vote, apply-coupon,
   accept-invite.
2. Fire **N concurrent requests** at the window. Use single-packet /
   last-byte-sync when HTTP/2 is available, else a parallel `curl` /
   `asyncio`+`httpx` burst.
3. Confirm the limit-once operation happened M>1 times (double-spend,
   coupon reuse, balance overrun).

## 4. Lane C — Economic / quantity logic

Negative or fractional quantities, currency/rounding abuse, price
tampering, refund > purchase, stacking single-use discounts.

## 5. Lane D — Privilege & ownership logic

Role transitions that skip approval, ownership reassignment,
tenant-boundary violations driven by workflow rather than direct authZ.

## 6. Proof & report

State the invariant violated and the concrete impact (money, data,
privilege) with before/after state. `bounty_scope_check`, then
`report_hackerone` / `report_bugcrowd_csv`. `h1_search` for disclosed
logic/race chains.
