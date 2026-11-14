# Phase C Research — Corroboration for Finding Accuracy

> Goal: make Buggy's findings accurate enough that a maintainer trusts them without hours of triage.
> Method: three parallel researchers on diverse models (Claude coordination/theory, GPT-5.6 technical/source-reading, Grok practitioner). Each required dated citations and a HIGH/MEDIUM/LOW confidence tag. Where the three agree, the signal is strong because the models are independent. Compiled 2026-11-13.
> Confidence: HIGH = primary source/code read directly. MEDIUM = reputable secondary/vendor. LOW = inferred. Unconfirmed numbers are flagged, per the standing rule that borrowed stats without a primary source are not cited as fact.

## 1. The problem the evidence describes

The 2025–2026 failure of AI security tooling is not missed bugs. It is false positives that cost humans hours to disprove.

- curl (Daniel Stenberg, "Death by a thousand slops," 2025-07-14): ~20% of 2025 submissions were AI slop, ~5% genuine; "every report engages 3-4 persons, up to an hour or three, each." curl ended its bug bounty in early 2026 to kill the incentive. HIGH (primary blog).
- HackerOne paused the Internet Bug Bounty (2026-04) and Google paused its OSS VRP (2026-10), both citing a flood of automated, mostly-invalid submissions. MEDIUM (secondary + Google's own statement).
- Independent benchmark (Stanford/CMU/Gray Swan, ~8,000-host live network, via HackerOne 2025-12-17): the best AI agent still had an 18% false-positive rate while humans were near-perfect, and agents "misread HTTP 200 responses and reported successful authentication even when logins failed." MEDIUM (reputable summary of a named study). The HTTP-200 hallucination is the canonical class the gate must catch.
- Hands-on Strix test (StrayVoltage, 2025-08): weak black-box param discovery, ~1M tokens to validate one XSS it was pointed at, opaque progress. MEDIUM (detailed primary test).

Flagged UNCONFIRMED: XBOW "zero false positives" and "200 zero-days" (blog 404s; deck says 174 reported / 22 CVEs), Strix "96% XBEN" (vendor/community, no independent replication), IBB valid-rate percentages (sources conflict). Treat all vendor "zero FP" framing with skepticism; XBOW's own later writing lists "zero FP" as a vendor red flag.

## 2. The one principle all three researchers reached independently

Never let the model that discovers a finding be the thing that certifies it. Accuracy comes from a check that is independent of the generator and re-derives the result from ground truth.

- Self-consistency, verifier models, and factored Chain-of-Verification all improve correctness, and all share one property: the checking signal does not reuse the finder's context (self-consistency: separate samples; verifiers: a separate model; factored CoVe: separate prompts that cannot see the draft). HIGH (arXiv:2203.11171, 2110.14168, 2309.11495).
- Intrinsic self-correction with no external signal often degrades accuracy ("LLMs Cannot Self-Correct Reasoning Yet," ICLR 2024, arXiv:2310.01798). HIGH. A validator that reuses the finder is the weakest form and can backfire.
- XBOW's Bayesian base-rate argument (Black Hat USA 2025 deck): vulns are rare, so even a 99%-accurate LLM "is this real?" yields mostly false positives among its hits. The fix is deterministic, non-AI validation of agent-supplied evidence. HIGH (deck read directly).
- Risk if ignored: if a validation agent inherits the same model and the same misreadings, coordination launders a hallucination into a "confirmed" finding instead of catching it. MEDIUM (synthesized from the 18% benchmark).

## 3. Techniques to adopt, from source we read directly

### From Strix (`usestrix/strix`, Apache-2.0, code read directly — HIGH)
- The reporting schema is the proof gate, enforced in code: `poc_script_code` REQUIRED, `http_exchange_ids` verified against the live proxy (unknown IDs rejected), mandatory `counterevidence` and machine-readable `confidence` + rationale. A built-in red-team step at the schema level.
- Coverage/closure ledger (`tools/coverage`, `skills/analysis/counterevidence.md`): every agent records what it examined and how it closed, with three states: `confirmed` (PoC or full source→sink trace + reachability), `ruled_out` (must name a specific control at a specific location on every attacker-reachable path, before the sink, no fail-open), `needs_follow_up` (plausible but unconfirmed, never silently dropped). The ledger is cross-agent and correctable: a `ruled_out` whose named control does not cover a newly-found path goes back to `reported`, prior state kept as history. This is the single most transferable idea for Phase C.
- Shared threat model at the root; subagents `amend` with attributed addenda, never overwrite. "Five agents without one shared answer to who the attacker is derive five answers that cannot be reconciled."
- Dedup: deterministic for CVEs, LLM-judge for dynamic findings on root-cause/fix identity ("would one patch fix both?"), judge must cite an existing ID, "when unsure, not a duplicate."
- Finish gate: the run cannot end with unexamined surfaces masquerading as clean.

### From Shannon (`KeygraphHQ/shannon`, AGPL-3.0, design only — clean-room, do not copy code — HIGH)
- "No exploit, no report." A queue-validation failure throws rather than returning "no vulnerabilities," because "laundering a failure into a clean verdict renders an un-assessed class as clean." Refuse to convert an error into a false-negative.
- Decorrelated validator stages (Capella, derived from Mantis Apache-2.0): a `review` stage instructed to "assume every finding is a false positive, ignore the original finder's prose reasoning, it may be hallucinated," then an adversarial `critic` stage that re-verifies independently. Set accounting quarantines ungraded findings so nothing silently appears or vanishes.
- Provenance enforcement: the SAST source location in the report can only come from the SAST engine, stripped from any value the writer agent carries and re-attached from the authoritative lane by an immutable join key. Prevents the LLM from minting a file:line.
- Their own benchmark's single false positive was an intended admin feature (the business-logic class), and their stated fix is cross-model corroboration: "a second model verifying trust boundaries would likely have caught it." Direct evidence for Phase C. MEDIUM (self-reported numbers).

### From the literature (primaries read — HIGH unless noted)
- Dynamic reproduction as the only accept gate: Google Big Sleep accepts a bug only on a crash under a debugger, and seeds from a recent commit diff (variant analysis) so the agent starts from a theory. FUGIO/NAVEX generate and run an actual working exploit.
- Reachability to suppress unexploitable SAST hits (CodeQL taint): a finding needs a source→sink path with taint traversal. Caveat to encode: reachability is approximate, so aggressive pruning trades false positives for false negatives. Vendor pruning percentages (92%, 60–95%, 25%) are UNCONFIRMED.
- LLM-as-judge has systematic position/verbosity/self-enhancement bias (arXiv:2306.05685) and run-to-run variance (arXiv:2412.12509). Mitigate: swap candidate order and require agreement, rubric-constrained scoring, sample more than once, never single-shot a Critical/High verdict.
- Cross-model "consortium consistency" (arXiv:2510.19507) beats single-model self-consistency because the models differ in training data and architecture. SelfCheckGPT (arXiv:2303.08896): facts stay consistent across samples, hallucinations diverge.
- Evaluation oracles never trust the agent's self-report: CVE-Bench grades eight observable server-side state changes; Cybench authors caught agents gaming the oracle; BountyBench requires an exploit to pass on the vulnerable snapshot and fail on the patched one. The recurring failure mode everywhere is the agent that correctly describes a vuln but cannot produce the state-changing proof.

### Theory (coordination researcher — HIGH on primaries)
- Blackboard systems (Hearsay-II, 1980): independent knowledge sources never talk directly, they read/write one shared structure, and agreement across independent sources promotes a hypothesis. Independence of the sources is what makes agreement meaningful.
- Corroboration as a separate object (TRACE-CTI): raw evidence immutable, agreement recorded as a distinct `consensus` object that does not by itself confer trust, and the authors warn that agreement does not establish statistical independence of the agreeing setups. Almost exactly the Phase C gate.
- Failure modes that HURT accuracy: debate can reduce group accuracy, a weaker agent drags down a stronger one, and longer debate is worse ("Talk Isn't Always Cheap," arXiv:2509.05396, MEDIUM; most degradation evidence traces to this one paper). Echo chambers and hallucination cascades amplify errors. Mitigations: information barriers between finder and corroborator, devil's-advocate roles, external validation checkpoints, enforced source independence, a capable verifier.

## 4. Revised Phase C design

Three layers: agents propose, the graph records corroboration as data, a deterministic engine decides. This is the "AI reads, deterministic engine decides" pattern applied to publishing a finding.

### Layer 1 — agents propose, never publish
Each discovery agent writes a `CandidateFinding` node to the Neo4j KG, never a published finding. Required fields: a structured `claim` (vuln class, asset, location), `evidence[]` each with provenance (agent id, tool, immutable raw-output id, and evidence modality: static-match, dynamic-probe, response-diff, canary, log-event), and the agent's source lineage so independence can be computed. Evidence nodes are immutable. This reuses Buggy's existing proof gate (a live HTTP exchange must back the claim) as the Layer-1 admission check.

### Layer 2 — the closure ledger, with independence enforced
Adopt Strix's three closure states as node states: `confirmed`, `ruled_out` (must name a specific control on every attacker-reachable path), `open_proof_gap`/`needs_follow_up` (never silently dropped). Any agent can update another agent's node, prior state kept as history, and a `ruled_out` re-opens when a newly-found path isn't covered by its named control.

Corroboration is a separate `Corroboration` edge carrying its own evidence and provenance, produced by an independent validator spawned with an information barrier: it gets the target (asset + claim type) but not the finder's prose reasoning (Shannon's "ignore the finder's story," factored CoVe). Prefer a different model for the validator. A devil's-advocate agent logs disconfirming evidence as a `Contradiction` edge. No LLM-vote-only consensus, and cap iteration rounds to avoid echo-chamber degradation.

### Layer 3 — deterministic gate (plain code, no LLM, no SMT solver)
A pure, reproducible function over KG state decides publish/hold/reject:

```
publish(finding) :=
    corroboration_count(finding, distinct_modality=True) >= 2
    AND source_independence(corroborating_sources) == True   # different agent AND tool-family AND context
    AND no_open_contradiction(finding)
    AND provenance_resolves(finding)                          # every evidence node -> an immutable raw-output record
  else HELD (needs corroboration) or REJECTED (contradicted)
```

The independence check is the crux: two agreements from the same agent/tool/context count as one. The gate is deterministic and auditable: identical graph state yields an identical decision with a logged reason trace.

Design note, aligned with the simplicity preference: this gate is boolean logic over graph counts. It does NOT need an SMT solver (FormalJudge/Z3 appears in the literature but is over-engineering here). Plain Python over the KG is correct, cheaper, and easier to audit. Reserve cross-model consensus (Layer 2) for exactly the un-oracle-able classes XBOW and Shannon both name: IDOR and business logic, where no canary or deterministic replay can settle it.

### Reportable accuracy metric
Adopt "verified, non-conflicted coverage": the fraction of findings with >=2 independent corroborations and zero open contradictions. This is a defensible KPI to publish instead of a vendor leaderboard score, and it directly answers the practitioner demand for a measured false-positive rate.

## 5. Improvements to the full Buggy, beyond Phase C

Drawn from the same evidence, these raise accuracy across the tool:
1. Harden the existing proof gate against Buggy's own agents gaming it: pin every deterministic check to the expected target host and scheme (XBOW's gamed-validator lessons, e.g. a validator that accepts `javascript:alert()` or `console.log()` as XSS).
2. Add canary-based validators where possible: plant a `flag{uuid}` an attacker shouldn't reach (file-read/RCE/SSRF/SQLi) and accept only an exact match. For time-based SQLi, replay `SLEEP(1)` vs `SLEEP(5)` and measure the delta in deterministic code.
3. Enforce evidence provenance: any static file:line on a finding must come from the SAST lane by immutable join key, never minted by the writer agent (Shannon pattern, clean-room).
4. Gate `finish` on reconciliation: refuse a silent-clean run; surface every `needs_follow_up` as an explicit area for review.
5. Dedup on root-cause/fix identity, deterministic-first, LLM-judge order-swapped and must cite an existing node id.
6. Be honest in output: report severity, blast radius, and the domains where Buggy is not validated. "A validated finding is not a triaged one."

## 6. Flagged disagreements and caveats
- The three researchers did not disagree on the core principle. The only tension is dosage: the coordination researcher is more optimistic about multi-agent corroboration, the practitioner evidence warns it can multiply noise if the validator shares the finder's model. Resolved by the independence requirement in Layer 2 and a different-model validator.
- Grok's live X/Twitter access failed this run (API key rejected), so practitioner X sentiment is only as quoted in secondary sources. A live-X pass is still open if wanted.
- Shannon is AGPL-3.0: design adopted clean-room, no code copied, consistent with keeping Buggy's license clean.
- Vendor accuracy numbers (XBOW, Shannon's own benchmark, reachability pruning percentages) are MEDIUM at best and flagged above; none are load-bearing for the design.

## 7. Primary sources (read directly)
Strix `github.com/usestrix/strix`; Shannon `github.com/KeygraphHQ/shannon` (design only); XBOW Black Hat USA 2025 deck; Hearsay-II (IJCAI 1977); self-consistency arXiv:2203.11171; verifier models arXiv:2110.14168; Chain-of-Verification arXiv:2309.11495; self-correction limits arXiv:2310.01798; LLM-judge bias arXiv:2306.05685; consortium consistency arXiv:2510.19507; SelfCheckGPT arXiv:2303.08896; CVE-Bench arXiv:2503.17332; Cybench arXiv:2408.08926; BountyBench arXiv:2505.15216; curl "Death by a thousand slops" (daniel.haxx.se, 2025-07-14); Stanford/CMU/Gray Swan benchmark via HackerOne (2025-12-17).
