---
name: ssrf-cloud-metadata
description: Hunt Server-Side Request Forgery and escalate it — confirm via out-of-band callback, bypass filters (IP encodings, DNS rebinding, redirect/gopher smuggling), pivot to internal services, and (only when authorised) reach cloud-metadata endpoints for IAM credentials.
metadata:
  subdomain: web-exploitation
  when_to_use: "ssrf server side request forgery cloud metadata 169.254.169.254 imds imdsv2 iam credentials dns rebinding gopher redirect filter bypass internal pivot webhook url fetch"
  mitre_attack: T1190, T1552.005
---

# SSRF & Cloud-Metadata Playbook

SSRF is the gateway to the internal network and the cloud control plane.
A single SSRF into a metadata endpoint can yield IAM credentials and
full account compromise — but metadata is **off by default** here.

## 0. Deterministic first

Do not hand-craft what code already does. Before any manual testing:

1. `recon_summary`, then `recon_query` for the record types this class needs
   (`endpoint`, `api_operation` (parameters named `url`, `uri`, `image`, `callback`, `webhook`, `import`)). The pipeline has already enumerated them; never re-crawl.
2. Run the probe below through `probe_run`. It sends the requests through the
   evidence gateway (scope-checked, rate-limited, recorded) and returns
   `vulnerable: true | false | null` with capture ids. `null` means the probe
   could not tell — it is not a negative.
3. Spend reasoning only on what the probe cannot decide: which objects and
   accounts to feed it, and how a confirmed primitive chains to impact.

**Probe `ssrf_canary`** — params `url`, `method`, `body` with `{{CANARY}}`
where the URL goes, optional `headers`, `wait_seconds`. It mints a one-time
callback URL, sends the request, and reports `true` only when the server
actually fetched it. No callback listener configured → `null`, never a guess.
State-changing (the endpoint usually stores something). Do not point SSRF at
cloud-metadata or internal addresses unless the program's scope names them;
the gateway refuses internal addresses that are not in scope.

Evidence: every finding cites the capture ids returned by the probe or by
`http_send`, and must pass `capture_verify` (the request replays against the
in-scope target with the same result). State-changing probes are held for the
operator's approval on real programs.

Proven in the lab: `packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_ssrf_probe_finds_profile_image_ssrf` finds Juice
Shop's profile-image SSRF by callback; `::test_ssrf_probe_does_not_flag_an_endpoint_that_stores_text`
is the negative control.

## 1. Scope gate (read first)

Cloud-metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, GCP
`metadata.google.internal`, Azure IMDS) are out-of-scope by default and
blocked at the sandbox edge. Only target them when the program
explicitly authorises metadata testing **and** scope was ingested with
`ingest_bounty_scope(allow_cloud_metadata=True)`. Otherwise prove SSRF
reach with an in-scope / out-of-band target instead.

## 2. Lane A — Find URL sinks

Webhooks, link previews, PDF/image fetchers, import-from-URL, SSO
metadata URLs, file-upload-via-URL, and any param that smells like a
URL/host.

## 3. Lane B — Confirm (always before claiming)

Inject a collaborator URL you control; confirm server-side fetch via an
out-of-band DNS/HTTP hit (`interactsh`-style listener). A 500 error is
**not** proof.

## 4. Lane C — Filter bypass

Alternate IP encodings (decimal, octal, IPv6-mapped), `@`-confusion in
the authority, open-redirect chaining, DNS rebinding, and
`gopher://`/`dict://` smuggling where the fetcher allows it.

## 5. Lane D — Escalate (only when authorised)

- **AWS IMDSv2** — `PUT /latest/api/token` (with TTL header) then `GET`
  with the `X-aws-ec2-metadata-token` header.
- **GCP / Azure** — require their metadata header
  (`Metadata-Flavor: Google` / `Metadata: true`).
- Retrieve instance credentials and demonstrate their (in-scope) reach.

## 6. Lane E — Internal pivot

Port-scan internal ranges, hit internal-only admin/health endpoints,
smuggle non-HTTP protocols where viable.

## 7. Proof & report

Capture the credential / internal response showing impact.
`bounty_scope_check`, then `report_hackerone` / `report_bugcrowd_csv`.
Use `cve_poc_lookup` for product-specific SSRF chains.
