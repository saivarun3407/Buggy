# XBOW Benchmark — Cross-Project Comparison

Side-by-side numbers for AI / LLM pentesting agents that have **publicly released results on the
[XBOW Validation Benchmark](https://github.com/xbow-engineering/validation-benchmarks)** (104 web-app CTF challenges, 3 difficulty tiers).

> **Buggy is currently unranked.** Its historical `102 / 104` claim is
> invalid because the former evaluator derived the expected flag from the
> public challenge ID. That result cannot establish exploitation and must not
> be compared with other systems. The provider now uses a random per-run secret;
> no fresh full-suite result has been published.

- **Historical mode** — black-box (no source code, config, or service internals), with challenge vulnerability tags supplied as engagement context.
- **Historical artifacts** — retained for audit, not as performance evidence, in [`benchmark/results/README.md`](../benchmark/results/README.md).
- **Review evidence** — [`docs/research/buggy-review-2026-11-17.md`](research/buggy-review-2026-11-17.md).

## Leaderboard

| # | System | XBOW Score | Mode | Source |
|--:|---|---|---|---|
| — | **Buggy** *(this repo)* | **No valid current score** — historical result invalidated | black-box, LangGraph multi-agent | [review](research/buggy-review-2026-11-17.md) |
| 1 | **PentestGPT** (USENIX '24)          | **86.5 %** (90 / 104)   | black-box                 | [github](https://github.com/GreyDGL/PentestGPT) · [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) |
| 2 | **Red-MIRROR**                       | **86.0 %**              | black-box, multi-agent + RAG | arXiv [2603.27127](https://arxiv.org/abs/2603.27127) |
| 3 | **XBOW** (commercial)                | **≈85 %**               | black-box, proprietary    | [xbow.com/blog/benchmarks](https://xbow.com/blog/benchmarks) |
| 4 | **Cyber-AutoAgent** (westonbrown)    | **84.62 %** (88 / 104) — v0.1.3 [archived]; 81 % v0.1.1; 45.92 % (45/98) v0.1.0 | black-box, meta-agent | [github](https://github.com/westonbrown/Cyber-AutoAgent) |
| 5 | **MAPTA**                            | **76.9 %** (80 / 104)   | black-box, multi-agent    | arXiv [2508.20816](https://arxiv.org/abs/2508.20816) |
| 6 | PentestAgent                         | 50.0 % [^retest]        | black-box                 | arXiv 2411.05185; re-tested in Red-MIRROR |
| 7 | AutoPT                               | 46.0 % [^retest]        | black-box                 | re-tested in Red-MIRROR |
| 8 | VulnBot                              |  6.0 % [^retest]        | black-box, baseline       | arXiv [2501.13411](https://arxiv.org/abs/2501.13411); re-tested in Red-MIRROR |


[^retest]: 50 % / 46 % / 6 % numbers come from the **Red-MIRROR ablation** re-running these systems on XBOW, not from the systems' own papers (VulnBot's own paper uses AutoPenBench).

## Per-Difficulty (where published)

| System | L1 | L2 | L3 | Total |
|---|---|---|---|---|
| **PentestGPT**  | 42 / 46 — 91.1 %     | 43 / 50 — 74.5 %             | 5 / 8 — 62.5 %    | **86.5 %**  |

Buggy's former per-difficulty values are omitted because they came from the
invalidated evaluation.

PentestGPT per-level avg cost / time: L1 $0.65 / 4.4 min · L2 $1.33 / 6.9 min · L3 $3.03 / 12.9 min (median across all 104: $0.42 / 3.3 min).
XBOW commercial does not publish a per-difficulty breakdown for its own agent — only the headline 85 % vs the senior pentester's 85 % in 40 hours.

## Historical Buggy Per-Vulnerability Artifact

The table below was generated from the invalidated Buggy result set. It is
retained only to preserve the audit trail and must not be interpreted as
confirmed exploit coverage or compared with valid benchmark results.

| Class | Total | Solved | Rate |
|---|---:|---:|---:|
| Broken Authorization | 25 | 25 | **100 %** |
| SQL Injection        |  7 |  7 | **100 %** |
| Blind SQLi           |  3 |  3 | **100 %** |
| XSS                  | 23 | 22 | 95.65 % |
| SSRF / Misconfig     | 22 | 21 | 95.45 % |
| SSTI                 | 13 | 12 | 92.31 % |
| Command Injection    | 11 | 10 | 90.91 % |
| **Total**            | **104** | **100** | **96.15 %** |

**MAPTA** per-class (overall 76.9 %): SSRF 100 % · Misconfig 100 % · SSTI 85 % · SQLi 83 % · Broken Authz 83 % · Cmd-Inj 75 % · XSS 57 % · Blind SQLi 0 %.

Historical Buggy per-class artifacts are indexed in
[`benchmark/results/README.md`](../benchmark/results/README.md).

## Adjacent — Don't Publish XBOW (different benchmark)

| Project | Benchmark used |
|---|---|
| **CAI** ([aliasrobotics/CAI](https://github.com/aliasrobotics/CAI)) | CAIBench |
| **xOffense** (arXiv [2509.13021](https://arxiv.org/abs/2509.13021)) | AutoPenBench (72.72 %) |
| **HackSynth** | 200-challenge picoCTF + OverTheWire |
| **HexStrike**, **PentestAgent (testified-oss)** | none reported |
| **MHBench** ([bsinger98/MHBench](https://github.com/bsinger98/MHBench)) | multi-host network red-team benchmark |

## Sources

- XBOW corp — [top-1 blog](https://xbow.com/blog/top-1-how-xbow-did-it) · [1060 attacks](https://xbow.com/blog/we-ran-1060-autonomous-attacks) · [benchmarks page](https://xbow.com/blog/benchmarks)
- Cyber-AutoAgent — [v0.1.0 results](https://github.com/westonbrown/Cyber-AutoAgent/discussions/12) · [Brown — *From Single Agent to Meta-Agent*](https://medium.com/data-science-collective/from-single-agent-to-meta-agent-building-the-leading-open-source-autonomous-cyber-agent-e1b704f81707) (v0.1.1 ≈81 % on 104; v0.1.0 45.92 % on 98)
- PentestGPT XBOW suite — [DeepWiki](https://deepwiki.com/GreyDGL/PentestGPT/5.1-xbow-validation-suite) (90/104 = 86.5 %; L1 42/46 · L2 43/50 · L3 5/8)
- MAPTA — [arXiv 2508.20816](https://arxiv.org/abs/2508.20816) (80/104 = 76.9 %)
- Red-MIRROR — [arXiv 2603.27127](https://arxiv.org/abs/2603.27127) (86.0 %; PentestAgent 50 %, AutoPT 46 %, VulnBot 6 % numbers also come from this paper's re-test of those systems)
- Survey — [*AI Pentesting Agents 2026*](https://appsecsanta.com/research/ai-pentesting-agents-2026)
- Awesome list — [insidetrust/awesome-ai-pentest](https://github.com/insidetrust/awesome-ai-pentest)

> *Last updated: 2026-05-17.*
