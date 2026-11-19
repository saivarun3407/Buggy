# Shared contracts (all task agents build against these)

## Roots (who can read and write what)

| Root | Env | In containers | Written by | Agent can read |
|---|---|---|---|---|
| workspace | `BUGGY_WORKSPACE_ROOT` | `/workspace` | agent sandbox | yes |
| control | `BUGGY_CONTROL_ROOT` | `/control` | operator CLI only | yes (read-only) |
| audit | `BUGGY_AUDIT_ROOT` | `/audit` | langgraph, guard, gateway | no |
| capture data | `BUGGY_CAPTURE_DATA` | `/data/capture` | capture service only | through MCP tools only |
| secrets | `BUGGY_SECRETS_ROOT` | `/secrets` | operator CLI only | **never** |
| recon store | `BUGGY_PIPELINE_DATA` | `/data/pipeline` | pipeline worker | through MCP tools only |

Per engagement everything lives under `<root>/<engagement>/`.

## Finding (the one schema; `buggy/findings/model.py` owns it)

```json
{
  "id": "F-<12 hex of sha256(engagement|class|normalized endpoint|parameter)>",
  "engagement": "acme",
  "title": "IDOR on GET /api/orders/{id}",
  "class": "access_control",
  "cwe": "CWE-639",
  "severity": "high",
  "endpoint": "https://app.acme.test/api/orders/{id}",
  "method": "GET",
  "parameter": "id",
  "source": "probe:idor | agent:<role> | pipeline:nuclei",
  "description": "...",
  "remediation": "...",
  "assertions": [
    {"capture_id": "cap-...", "identity": "", "expect": {"status": 200, "body_contains": ["bob@"], "body_not_contains": [], "differs_from": "cap-...", "same_as": "cap-..."}}
  ],
  "status": "candidate | exploit_verified | source_verified | inconclusive | discarded",
  "verification": {"at": 0.0, "replay_capture_ids": [], "reasons": []},
  "grade": "submit | hold | discard | null",
  "grade_reasons": [],
  "created_at": 0.0, "updated_at": 0.0
}
```

`class` is one of `benchmark/lab/taxonomy.py::CLASSES`. `severity` is one of
`critical, high, medium, low, info`. Only `exploit_verified` findings are "findings" in
reports, gates and counts; everything else is listed separately and labelled.

## Stores (all SQLite, rollback journal, one file each, under capture data)

| File | Module | Purpose |
|---|---|---|
| `captures.sqlite3` | `buggy/capture/store.py` (exists) | recorded requests |
| `findings.sqlite3` | `buggy/findings/store.py` | findings + candidates queue |
| `lessons.sqlite3` | `buggy/memory/lessons.py` | cross-engagement lessons |
| `board.sqlite3` | `buggy/coordination/board.py` | facts / intents / hints |

## Reserved MCP tool names (the integrator wires them; do not register them yourself)

`finding_submit, finding_get, findings_list, finding_verify, finding_grade, candidates_next,
report_build, evidence_export, identities_list, authz_matrix_run, memory_search, memory_save,
fact_add, facts_list, intent_open, intent_claim, intent_conclude, hints_list, hint_add,
program_brief`

Expose plain Python functions/classes that return JSON-serialisable dicts. No FastMCP code.

## Existing interfaces you can rely on

- `buggy.capture.gateway.CaptureGateway(roots, opener=..., sleep=...)`:
  `.send(engagement, method, url, *, headers=None, body=None, note="", probe="", replay_of="") -> Capture`,
  `.replay(engagement, capture_id) -> dict` (`reproduced`, `same_status`, `replay`),
  `.verify(engagement, capture_id, expect_host="") -> dict`, `.store` (`CaptureStore.get/list`),
  raises `GatewayRefusal(code, detail)`.
- `buggy.capture.store.Capture`: `id, method, url, host, status, request_headers,
  request_body, response_headers, response_body (bytes), response_sha256, response_bytes,
  elapsed_ms, probe, note, replay_of, error`; `.summary()`, `.detail()`.
- `buggy.capture.probes.base`: `Context(gateway, engagement, probe, canary).send(...)`,
  `ProbeResult(probe, vuln_class, cwe, vulnerable: bool|None, summary, evidence, details,
  remediation)`, `ProbeSpec`, helpers `require, headers_of, ok, text, json_of, similarity`.
  `vulnerable=None` means "could not tell" and must never be reported as a pass or a fail.
- `buggy.pipeline.store.ReconStore`, `buggy.pipeline.schema.Record/RecordType`,
  `buggy.pipeline.scope.ScopeFilter.from_document(doc)` (`.allows(x)`, `.decide(x)`, `.limits`).
- Test doubles to copy: `packages/buggy/tests/unit/capture/test_gateway.py::Site` (fake
  origin), `packages/buggy/tests/unit/pipeline/test_pipeline_flow.py::FakeTools`.
- New CLI commands: create `packages/buggy/buggy/cli/<name>.py` with
  `main(argv: list[str] | None = None) -> int`. `buggy-cli <name>` dispatches to it
  automatically (dashes become underscores). Do not edit `cli/__main__.py`.
