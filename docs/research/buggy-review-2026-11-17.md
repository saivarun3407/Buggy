# Buggy engineering review — 2026-11-17

Revision: `7d67e8a5ba56e98566e1586a12c6c82c8c38185c`, clean working tree.

**Assessment: substantial engineering foundation, with release-blocking correctness problems in the current finding lifecycle.** Buggy has useful infrastructure, real tests, and historical execution artifacts. The current code does not yet support its strongest claims about independent verification, immutable evidence, or reliable report publication. More specialist agents would not resolve these problems.

> **Historical review snapshot:** this document records the defects found at the
> revision above. The accompanying fixes were implemented after the review and
> are covered by regression tests in the reporting, coordinator, KG, and
> benchmark suites. Keep this report as the rationale and evidence trail, not as
> a description of the current implementation.

This was a broad review of critical execution and reporting paths, not an exhaustive audit of every file or an autonomous penetration test. Source findings below are separated from direct reproductions and operational observations. No application code was changed.

## Evidence gathered

| Check performed in this review | Result |
|---|---|
| Reporting, agent, middleware, and benchmark unit tests | **1,756 passed; 3 skipped** |
| Existing KG integration suite against running Neo4j | **40 passed** |
| Ruff check over reporting, KG internals, coordinator, benchmark | Passed |
| Ruff format check over those modules | **61 files already formatted** |
| Independent live graph reproductions | Lifecycle blockage, export bypass, weak evidence resolution, stale retraction, and missing report fields reproduced |
| Coordinator lifecycle reproduction | ID/parent reused; second completion missing; status remains running |
| Proof gate with a controlled unrelated-host capture response | Accepted and marked `live_verified=True` |
| XBOW scorer with a locally calculated flag and no target | Returned `passed=True` |
| Container inspection | Six services healthy; solver unhealthy; running LangGraph uses an older Decepticon tree |

The unit skips cover disabled telemetry, an unavailable optional `transformers` dependency, and a benchmark harness mock that needs an SDK-compatible rewrite. The focused suite does not re-establish the historical full-suite count.

The original isolated reproduction script used a UUID-scoped Neo4j engagement
and deleted only its own nodes. Its cases have since been converted into
repository regression tests; the temporary script is intentionally not shipped.

## Prioritized findings

### 1. P1 — New findings cannot complete the default publication lifecycle

**Sources:** `packages/buggy/buggy/tools/reporting/tools.py:202-226`; `packages/buggy/buggy/tools/reporting/kg_adapter.py:186-202,233-241`.

`record_finding()` requires corroborations before it creates the Finding node. `submit_corroboration_observation()` refuses a finding key unless that Finding node already exists. A held result returns only a response; it creates no candidate.

**Live reproduction:** the first report returned `open_proof_gap` with zero corroborations. Submitting corroboration for its canonical key then raised “no Finding node in this engagement to corroborate.”

**Impact:** the normal first-finding path cannot progress through the default gate. Agents must use another write path or disable the requirement. Candidate storage is therefore a prerequisite for the enabled gate, rather than a minor deferred feature.

**Remediation:** persist a candidate before verification, with original finder identity, proof references, and state. Let validation reference candidates. Promote it atomically after successful verification. Return a stable candidate handle when held.

### 2. P1 — Alternate writes bypass verification; retracted findings remain exportable

**Sources:** `packages/buggy/buggy/middleware/kg_internal/tools.py:120-175`; `packages/buggy/buggy/tools/reporting/sarif.py:44-50`; `packages/buggy/buggy/tools/reporting/bugcrowd.py:44-51`; `packages/buggy/buggy/tools/reporting/tools.py:220-226`.

The agent-facing `kg_record` tool can create a Finding directly. Exporters select Finding/Vulnerability nodes without checking an authoritative publication state. On a later contradiction, `record_finding()` returns `ruled_out` without persisting that state or retracting the old node.

**Live reproduction:** one direct `kg_record` call produced one SARIF finding before either gate approved it. After recording a contradiction and receiving `state="ruled_out"`, the SARIF output still contained that finding.

**Impact:** the verification gate is optional in practice, and disconfirmed findings can survive in deliverables. The separate structured JSON export path also needs to participate in the same lifecycle.

**Remediation:** centralize report eligibility. Ordinary observation writes must not create confirmed publication state. Every renderer/exporter must require confirmed state, and a retraction must update persistent state immediately.

### 3. P1 — “Immutable raw evidence” is only a nonempty, mutable provenance string

**Sources:** `packages/buggy/buggy/tools/reporting/kg_adapter.py:303-318`; `packages/buggy/buggy/middleware/kg_internal/store.py:435-449`; `packages/buggy/buggy/tools/reporting/kg_adapter.py:126-131`.

`_evidence_resolves()` checks whether any matching node has a nonempty `source_episode_id`. It does not retrieve raw output, check an immutable artifact, validate a digest, or establish relevance to the claimed vulnerability. Every ordinary observation receives such a string.

**Live reproduction:** the Finding node itself qualified as evidence. Two corroborations from one validator using different tool-family strings and that same evidence node satisfied the gate. With no proxy client, the report was persisted with `success=True`, `evidence_unverified=True`, and `live_verified=False`.

Counting distinct `(agent, tool_family)` pairs is the implemented policy; this review does not treat that policy alone as a separate defect. The problem is that the evidence and its claimed origin are not verified.

The store also overwrites `created_by` and `source_episode_id` on updates. Publication changed the original finder to `proof_gate` and its anchor to the finding key. That loses original attribution used by the self-corroboration check.

**Impact:** recorded assertions can satisfy a check described as independent raw evidence. The contradiction path shares the same weakness, so unsupported assertions can also suppress findings.

**Remediation:** separate immutable evidence records from mutable observations. Verify artifact existence and integrity, bind each artifact to an actual tool execution and target, preserve original finder identity, and retain unverified candidates without publishing them.

### 4. P1 — Coordinator identity and completion state leak across invocations

**Sources:** `packages/buggy/buggy/middleware/coordinator.py:194-205,215-249,261-284`; `packages/buggy/buggy/agents/standard/buggy.py:155-163`; module-level graphs in `langgraph.json`.

The middleware holds `_agent_id`, `_node`, and `_completion_reported` on its Python instance. The orchestrator compiles each specialist once and reuses that runnable. Module-level graphs are also reused by the server.

**Direct lifecycle reproduction:** registering with `parent-A`, completing, then registering with `parent-B` on the same middleware produced the same ID and retained `parent-A`. The second completion produced no message. The node status remained `running` after completion.

**Impact:** successive objectives can collapse into one apparent agent, parent linkage becomes stale, and completion notifications disappear. Concurrent/restarted runs need further integration coverage; the sequential reuse defect is already demonstrated.

**Remediation:** scope identity and completion state to a durable invocation/run identifier, carried in graph/runtime state. Bind tools to that invocation and persist terminal status. Test repeated objectives, parallel same-role children, and resume.

### 5. P1 — A capture ID from an unrelated host is treated as live proof

**Sources:** `packages/buggy/buggy/tools/reporting/proof_gate.py:263-301,505-521`.

The capture check confirms the cited ID exists. It never compares the captured request with the finding's target. `live_verified` becomes true when IDs exist and no transport warning occurred.

**Controlled-response reproduction:** a finding for `https://review-target.invalid/login` cited a request returned as `https://unrelated.invalid/`; the gate accepted it and set `live_verified=True`.

**Impact:** evidence from another host or path can substantiate an unrelated claim. Nonempty PoC/evidence text and an existing request are insufficient to establish demonstrated impact.

**Remediation:** bind captures to engagement and expected origin, scheme, endpoint, method, and relevant input. Apply vulnerability-specific outcome checks where supported; otherwise label the result as a captured request awaiting impact verification.

### 6. P1 for evaluation credibility — XBOW scores can pass without exploitation

**Source:** `benchmark/providers/xbow.py:212-235`.

The expected flag is `FLAG{sha256(challenge.id.upper())}`. Evaluation searches the captured text for that string. The challenge ID is supplied to the solver.

**Direct reproduction:** a local calculation, placed into a single synthetic output step, returned `passed=True` with no target setup, no network request, and a nonexistent workspace.

**Impact:** a passing score is not sufficient evidence of exploitation. This does **not** prove any previous solver used the shortcut. Historical successful runs need trace-level validation before being used as capability evidence.

**Remediation:** generate a fresh unpredictable flag per run, inject it only into the target and trusted evaluator, and keep it out of solver-accessible setup data. Preserve target-side or replayable evidence. Record solver lane, model/configuration, code revision, image digest, and attempt index with each result.

### 7. P2 — Accepted PoC and target fields disappear from customer-facing exports

**Sources:** `packages/buggy/buggy/tools/reporting/tools.py:333-350`; `packages/buggy/buggy/tools/reporting/hackerone.py:84-96`; `packages/buggy/buggy/tools/reporting/bugcrowd.py:58-68`.

The recording tool stores `poc_script_code`, `poc_description`, `evidence`, and `target`. HackerOne and Bugcrowd renderers instead read legacy PoC fields such as `poc_command`/`stdout_excerpt`; Bugcrowd reads `url`/`file` for location.

**Live round-trip reproduction:** after publication and reloading the graph, neither export contained the supplied PoC sentinel or target URL.

**Impact:** the gate can demand proof that the resulting report omits. A reviewer receives an incomplete deliverable even when the data is present in storage.

**Remediation:** define one finding schema or explicit translation layer, and exercise record → reload → render for every supported format.

### 8. P2 — The dashboard and gated reporting read different finding stores

**Sources:** `clients/web/src/app/api/engagements/[id]/findings/route.ts:141-162`; `packages/buggy/buggy/tools/reporting/tools.py:236-250`; `packages/buggy/buggy/tools/reporting/kg_adapter.py:126-180`.

**Source-confirmed; no browser test performed.** The dashboard findings endpoint reads only `findings/FIND-*.md`. The gated recording path writes Neo4j and does not emit those Markdown files. The dashboard parser does not consult gate state.

**Impact:** a successfully published graph finding does not automatically appear in the dashboard. Separately written Markdown findings can appear without passing the same gate.

**Remediation:** make the dashboard a projection of the authoritative finding lifecycle, or add an explicit synchronized artifact producer with identical eligibility rules.

## Deployment and historical evaluation observations

- Docker currently reports healthy LangGraph, LiteLLM, Skillogy, sandbox, PostgreSQL, and Neo4j services. It is inaccurate to say no stack has ever run.
- The running LangGraph container's package tree is `/app/packages/decepticon*`. It has an older proof gate, no `corroboration_gate.py`, and no coordinator module. It does not validate the reviewed Buggy revision.
- The solver reports unhealthy. It inherits the LangGraph image's healthcheck for `localhost:2024/ok`, while its configured command is `sleep infinity`. The healthcheck does not match the solver's intended process, so this status alone does not establish solver failure. Override or remove that inherited healthcheck.
- The web container is not running. Frontend dependencies are not installed in this checkout. The dashboard observations above are source analysis, not a verified frontend build or browser result.
- `uv` is absent from PATH. Focused tests used the existing `.venv` directly. I did not claim `make ci-test`, the wheel build, or the complete quality gate passed.
- `make smoke` starts by purging containers and volumes. It was not run during this review because the existing stack contains data; read-only inspection and uniquely scoped KG tests supplied the deployment evidence instead.
- The historical 104-challenge batch records seven passes. Its actual result records classify as 62 build errors, two other errors, 33 misses without an error, and seven passes. Infrastructure failure prevents a meaningful capability interpretation, and deterministic flags further limit the strength of the successful results.
- Later small reruns are not a controlled full-suite evaluation. The result schema omits solver lane, model, and checkout/image identity, despite the harness supporting both Buggy and a separate Devin solver.
- The local Strix reference is `685bbc8` (v1.7.1); its benchmark directory contains a README rather than a matching scored run. No defensible Buggy-versus-Strix win-rate claim follows from these artifacts.

## What is working well

The code has explicit agent/tool/middleware extension contracts, safety-override gates, engagement-scoped graph operations, atomic observation batches, and untrusted-output handling. The 40 live database tests provide useful evidence about graph mechanics. The focused unit coverage exercises a substantial amount of orchestration and safety logic and remains green.

Those strengths support continued development. They do not compensate for a broken publication lifecycle. The evidence resolver tests largely accept canned anchors as valid evidence, and lifecycle tests can start from an already-existing Finding. That allows them to pass while missing the first real submission and the trust boundary around the anchor.

## Recommended order

1. Build the candidate → validation → confirmed/retracted lifecycle and make all exports enforce it. This resolves the first-finding blockage and closes alternate-write/reporting bypasses.
2. Preserve finder identity and create verifiable, immutable evidence records. Tie captured requests to the target and prevent unverified material from becoming published proof.
3. Move coordinator identity into invocation-scoped state and verify repeated/concurrent objectives.
4. Unify report field mappings and the dashboard projection.
5. Rebuild an isolated stack from a pinned revision and verify its image identity. Fix solver health semantics.
6. Run a reproducible evaluation with unpredictable flags, negative controls, pinned solver/model/configuration, all attempted targets accounted for, and retained traces. Report precision/recall only against known ground truth; report infrastructure failures separately.

**Readiness judgment:** suitable for development and supervised experiments. The present finding/reporting path needs correction before relying on it for unattended, accurate vulnerability deliverables. Its advantage over Strix remains unmeasured.
