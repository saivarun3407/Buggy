---
name: authn-session-takeover
description: Hunt authentication, federation, and session bugs that lead to account takeover — JWT attacks (alg confusion, none, kid injection), OAuth/OIDC/SAML flaws, password-reset and MFA bypass, and session-lifecycle issues. Chain primitives to a proven takeover.
metadata:
  subdomain: web-exploitation
  when_to_use: "authentication authorization session account takeover ato jwt alg confusion none kid oauth oidc saml sso password reset mfa bypass session fixation cookie federation"
  mitre_attack: T1078, T1539, T1606, T1110
---

# Authentication / Session Takeover Playbook

Account takeover (ATO) is the highest-payout class in most programs, and
it lives in the seams between identity components. The deliverable is a
proven takeover — you control the victim's session/account — not a
theoretical weakness.

## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`endpoint`, `api_operation`, `js_file`, `header`). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `jwt_alg_none`** — params `url` (a GET endpoint that requires the
token), `token` (a valid JWT for a test account), optional `header`,
`claim_overrides`, `headers`. It first proves the token works, then that a
garbage token is rejected, then sends the same claims with the signature
removed. Run it against several routes: frameworks often verify on one
middleware chain and not another. Not state-changing.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_jwt_probe_finds_unsigned_token_acceptance` finds
Juice Shop's unsigned-JWT acceptance; `::test_jwt_probe_does_not_flag_a_route_that_binds_tokens_to_sessions`
is the negative control.

## 1. Map the auth surface

Login, registration, password reset, MFA enrolment/verification,
SSO/federation, token issuance/refresh, logout. For each, state the
invariant it must hold (e.g. "reset token is per-account, single-use,
expiring").

## 2. Lane A — JWT / token attacks

- Decode first. Then test:
  - **alg confusion** — RS256→HS256 signing with the public key as the
    HMAC secret.
  - **`alg: none`** / missing signature verification.
  - **`kid` injection / path traversal** (point `kid` at a known file or
    SQL-inject it).
  - **weak HMAC secret** — crack with `hashcat`/`jwt_tool`.
  - claims trusted downstream (`role`, `admin`, `sub`) — tamper them.
  - expiry / replay handling.

## 3. Lane B — OAuth / OIDC / SAML

- `redirect_uri` validation gaps (open redirect → code/token theft).
- missing/replayable `state` (CSRF on the callback).
- authorization-code leakage/replay, PKCE downgrade, audience confusion.
- SAML: signature stripping, XML signature wrapping (XSW).

## 4. Lane C — Reset / registration / enumeration

- Reset-token entropy, reuse, no expiry; host-header poisoning of the
  reset link → token exfil.
- Pre-account-takeover via unverified email; username enumeration via
  timing/response diffs.

## 5. Lane D — Session lifecycle

- Session fixation; missing invalidation on logout / password change;
  concurrent sessions; cookie flags (HttpOnly / Secure / SameSite).

## 6. Proof & report

Demonstrate ATO end-to-end with captured requests showing the second
account compromised. `bounty_scope_check`, then `report_hackerone` /
`report_bugcrowd_csv`. `h1_search` is invaluable for disclosed ATO
chains.
