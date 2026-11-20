import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  buildSnapshot,
  engagementFile,
  evidenceFromResult,
  findingsFromResult,
  joinApprovals,
  nextActions,
  parseJsonl,
  reconFromSummary,
  rootsFromEnv,
  scopeFromDocument,
  statusResponse,
  toolFetchFromEnv,
  type FileIo,
  type Roots,
  type ToolFetch,
} from "./snapshot";
import { BODY_PREVIEW_CHARS, type StatusSnapshot } from "./shape";

const SLUG = "acme-test";
const NOW = 1_700_000_500;
const LONG_BODY = "A".repeat(300) + "TAIL-OF-THE-BODY-" + "B".repeat(4700);

let tmp: string;
let roots: Roots;
let secrets: string;

function jsonl(rows: unknown[]): string {
  return rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
}

function request(id: string, args: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    kind: "approval_request",
    request_id: id,
    engagement_name: SLUG,
    agent_name: "capture-gateway",
    tool_name: "http_send",
    tool_args_redacted: args,
    reason: `reason for ${id}`,
    created_at: 1_700_000_000,
    ...extra,
  };
}

function decision(id: string, action: string) {
  return { kind: "approval_decision", request_id: id, action, operator_note: "", decided_at: 1_700_000_100 };
}

before(async () => {
  tmp = await fsp.mkdtemp(path.join(os.tmpdir(), "status-route-"));
  roots = { control: path.join(tmp, "control"), audit: path.join(tmp, "audit") };
  secrets = path.join(tmp, "secrets");
  const control = path.join(roots.control, SLUG);
  const audit = path.join(roots.audit, SLUG);
  await fsp.mkdir(path.join(control, "approvals"), { recursive: true });
  await fsp.mkdir(path.join(audit, "approvals"), { recursive: true });
  await fsp.mkdir(path.join(secrets, SLUG), { recursive: true });
  await fsp.writeFile(path.join(secrets, SLUG, "identities.json"), '{"password":"never-read"}');

  await fsp.writeFile(
    path.join(control, "roe.json"),
    JSON.stringify({
      machine_enforcement: {
        mode: "enforce",
        in_scope: ["app.acme.test", { target: "*.api.acme.test", type: "domain-glob" }],
        out_of_scope: ["admin.acme.test"],
        min_inter_request_delay_ms: 250,
        sandbox_egress: "blocked",
      },
      approvals: { state_changing: "required" },
    }),
  );
  await fsp.writeFile(
    path.join(audit, "approvals", "requests.jsonl"),
    jsonl([
      request("apr-allowed", { method: "POST", url: "https://app.acme.test/a" }),
      request("apr-denied", { method: "DELETE", url: "https://app.acme.test/b" }),
      request("apr-pending", {
        method: "PUT",
        url: "https://app.acme.test/c",
        body_sha256: "0".repeat(64),
        body_preview: LONG_BODY,
      }),
      // The same request filed twice is one request.
      request("apr-pending", { method: "PUT", url: "https://app.acme.test/other" }),
      request("apr-flipped", { method: "POST", url: "https://app.acme.test/d" }),
    ]) + "not json at all\n",
  );
  await fsp.writeFile(
    path.join(control, "approvals", "decisions.jsonl"),
    jsonl([
      decision("apr-allowed", "allow"),
      decision("apr-denied", "deny"),
      // The last decision for a request is the one that counts.
      decision("apr-flipped", "allow"),
      decision("apr-flipped", "deny"),
      decision("apr-of-another-engagement", "allow"),
    ]),
  );
  await fsp.writeFile(
    path.join(control, "hunt-result.json"),
    JSON.stringify({
      engagement: SLUG,
      finished_at: 1_700_000_400,
      recon: { state: "completed", records: { subdomain: 4, url: 20 }, scope_drops: 3 },
      issues: { critical: 0, high: 1, medium: 2, low: 0, info: 5 },
      findings: {
        available: true,
        exploit_verified: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        inconclusive: 2,
        candidates: 1,
      },
      approvals_pending: 1,
      agent: { ran: true, error: null },
      complete: true,
      something_else: "not passed on",
    }),
  );
  await fsp.writeFile(path.join(control, "recon-report.md"), "# report\n");
  await fsp.writeFile(
    path.join(audit, "roe-decisions.jsonl"),
    jsonl([
      { ts: 1_700_000_010, tool: "execute", decision: "allow", event: "tool_call" },
      { ts: 1_700_000_020, tool: "execute", decision: "refuse", event: "tool_call" },
      { ts: 1_700_000_030, tool: "http_send", decision: "allow", event: "tool_call" },
    ]),
  );
});

after(async () => {
  await fsp.rm(tmp, { recursive: true, force: true });
});

/** A reader that answers like a stack with a recon run in progress. */
const stack: ToolFetch = async (server, tool) => {
  if (server === "recon" && tool === "recon_summary") {
    return {
      records: { url: 12, subdomain: 3, bogus: "x" },
      current_run: { run_id: "r1", started_at: NOW - 61.25, stage: "live", stages_done: ["enumerate", "dns"] },
      last_run: null,
    };
  }
  if (tool === "http_captures") return { count: 7, captures: [{ id: "cap-1", created_at: 1_700_000_040 }] };
  if (tool === "findings_list") {
    return {
      findings: [
        { id: "F-b", title: "Low one", severity: "low", class: "xss", status: "exploit_verified", grade: "hold" },
        { id: "F-a", title: "IDOR", severity: "high", class: "access_control", status: "exploit_verified" },
        { id: "F-c", title: "Maybe", severity: "critical", class: "sqli", status: "candidate" },
      ],
    };
  }
  return { error: "unexpected call" };
};

const unconfigured = toolFetchFromEnv({});

function recordingIo(): { io: FileIo; touched: string[]; read: string[] } {
  const touched: string[] = [];
  const read: string[] = [];
  const io: FileIo = {
    realpath: (file) => (touched.push(file), fsp.realpath(file)),
    stat: (file) => (touched.push(file), fsp.stat(file)),
    readFile: (file) => (touched.push(file), read.push(file), fsp.readFile(file, "utf-8")),
  };
  return { io, touched, read };
}

async function ok(deps: Partial<Parameters<typeof statusResponse>[1]> = {}): Promise<StatusSnapshot> {
  const response = await statusResponse("eng-id-1", {
    findEngagement: async () => ({ name: SLUG }),
    roots,
    fetchTool: stack,
    now: NOW,
    ...deps,
  });
  assert.equal(response.status, 200);
  return response.body as StatusSnapshot;
}

test("the route returns the snapshot for a fixture engagement, with the CLI's top-level keys", async () => {
  let asked = "";
  const snapshot = await ok({
    findEngagement: async (id) => {
      asked = id;
      return { name: SLUG };
    },
  });
  assert.equal(asked, "eng-id-1");
  // The keys of `buggy-cli status --json`, then the two the dashboard adds.
  assert.deepEqual(Object.keys(snapshot), [
    "engagement",
    "generated_at",
    "scope",
    "recon",
    "approvals",
    "evidence",
    "findings",
    "agents",
    "next",
    "hunt",
    "recon_report",
  ]);
  assert.equal(snapshot.engagement, SLUG);
  assert.equal(snapshot.generated_at, NOW);

  assert.deepEqual(snapshot.scope, {
    available: true,
    mode: "enforce",
    in_scope: ["app.acme.test", "*.api.acme.test"],
    out_of_scope: ["admin.acme.test"],
    rate_limit_rps: 4, // 1000 ms / 250 ms, below the default of 10
    sandbox_egress: "blocked",
    approvals: { state_changing: "required", report_submission: "not_required" },
    program: null,
  });
  assert.deepEqual(snapshot.recon, {
    available: true,
    state: "running",
    stage: "live",
    stages_done: ["enumerate", "dns"],
    started_at: NOW - 61.25,
    elapsed_s: 61.3,
    records: { subdomain: 3, url: 12 },
    scope_drops: null,
  });
  assert.deepEqual(snapshot.evidence, {
    available: true,
    count: 7,
    count_is_lower_bound: false,
    last_capture_at: 1_700_000_040,
  });
  assert.deepEqual(snapshot.agents, {
    available: true,
    last: { at: 1_700_000_030, tool: "http_send", decision: "allow", event: "tool_call" },
    allow: 2,
    refuse: 1,
  });
  assert.ok(snapshot.hunt.available);
  assert.equal(snapshot.hunt.complete, true);
  assert.deepEqual(snapshot.hunt.recon, { state: "completed", records: { subdomain: 4, url: 20 }, scope_drops: 3 });
  assert.deepEqual(snapshot.hunt.issues, { critical: 0, high: 1, medium: 2, low: 0, info: 5 });
  assert.equal(snapshot.hunt.findings.exploit_verified.high, 1);
  assert.deepEqual(snapshot.hunt.agent, { ran: true, error: null });
  assert.equal("something_else" in snapshot.hunt, false);
  assert.ok(snapshot.recon_report.available);
  assert.equal(snapshot.recon_report.present, true);
  assert.ok(snapshot.next.includes(`1 request waits for approval: buggy-cli approvals list ${SLUG}`));
  assert.ok(snapshot.next.includes(`Recon is running (stage: live): buggy-cli status ${SLUG} --follow`));
});

test("approvals are the requests joined with the operator's decisions", async () => {
  const { approvals } = await ok();
  assert.ok(approvals.available);
  assert.equal(approvals.total, 4); // the duplicate line and the malformed line add nothing
  assert.equal(approvals.pending, 1);
  assert.equal(approvals.allowed, 1);
  assert.equal(approvals.denied, 2); // apr-denied, and apr-flipped whose last decision is deny
  assert.equal(approvals.other, 0);
  assert.deepEqual(
    approvals.pending_requests.map((r) => r.request_id),
    ["apr-pending"],
  );
  const pending = approvals.pending_requests[0];
  assert.equal(pending.method, "PUT");
  assert.equal(pending.url, "https://app.acme.test/c"); // the first line for an id is the request
  assert.equal(pending.tool_name, "http_send");
  assert.equal(pending.reason, "reason for apr-pending");
});

test("joinApprovals: every request is pending until a decision names it", () => {
  const requests = [request("r1", {}), request("r2", {})];
  assert.equal(joinApprovals(requests, []).pending, 2);
  const joined = joinApprovals(requests, [decision("r2", "ALLOW"), decision("r1", "redirect")]);
  assert.deepEqual(
    { pending: joined.pending, allowed: joined.allowed, denied: joined.denied, other: joined.other },
    { pending: 0, allowed: 1, denied: 0, other: 1 },
  );
  // A decision for an unknown request decides nothing.
  assert.equal(joinApprovals(requests, [decision("r9", "allow")]).pending, 2);
  // Rows without a request id are not requests.
  assert.equal(joinApprovals([{ kind: "approval_request" }], []).total, 0);
});

test("a pending approval never carries more than a short preview of the request body", async () => {
  const snapshot = await ok();
  assert.ok(snapshot.approvals.available);
  const pending = snapshot.approvals.pending_requests[0];
  assert.equal(pending.body_preview, "A".repeat(BODY_PREVIEW_CHARS));
  assert.equal(pending.body_truncated, true);
  const wire = JSON.stringify(snapshot);
  assert.equal(wire.includes("TAIL-OF-THE-BODY"), false);
  assert.equal(wire.includes("A".repeat(BODY_PREVIEW_CHARS + 1)), false);

  // The same for a request that stores the body itself, as a string or as an object.
  for (const body of [LONG_BODY, { note: LONG_BODY }]) {
    const [item] = joinApprovals([request("r1", { method: "POST", url: "https://x.test/", body })], [])
      .pending_requests;
    assert.ok((item.body_preview ?? "").length <= BODY_PREVIEW_CHARS);
    assert.equal(item.body_truncated, true);
    assert.equal(JSON.stringify(item).includes("TAIL-OF-THE-BODY"), false);
  }
  // A tool call that is not an HTTP request: its arguments are cut the same way.
  const [tool] = joinApprovals([request("r2", { command: LONG_BODY }, { tool_name: "execute" })], [])
    .pending_requests;
  assert.ok((tool.args_preview ?? "").length <= BODY_PREVIEW_CHARS);
  assert.equal(JSON.stringify(tool).includes("TAIL-OF-THE-BODY"), false);

  // Control: a short body is shown whole and is not marked as cut.
  const [short] = joinApprovals(
    [request("r3", { method: "POST", url: "https://x.test/", body_preview: '{"qty":2}' })],
    [],
  ).pending_requests;
  assert.equal(short.body_preview, '{"qty":2}');
  assert.equal(short.body_truncated, false);
  assert.equal(short.args_preview, undefined);
});

test("a stored name that is not a slug is rejected before any file or server is touched", async () => {
  const payloads = ["../../etc", "..", "/etc/passwd", "a/../../b", `${SLUG}/../other`, ".hidden", "UPPER", "", "ab"];
  for (const name of payloads) {
    const { io, touched } = recordingIo();
    let calls = 0;
    const response = await statusResponse("eng-id-1", {
      findEngagement: async () => ({ name }),
      roots,
      io,
      fetchTool: async () => (calls++, {}),
      now: NOW,
    });
    assert.equal(response.status, 400, `expected 400 for ${JSON.stringify(name)}`);
    assert.deepEqual(response.body, { error: "Engagement name is not a valid workspace slug" });
    assert.deepEqual(touched, []);
    assert.equal(calls, 0);
    // The builders refuse the same names when called directly.
    await assert.rejects(buildSnapshot(name, { roots, fetchTool: stack, now: NOW, io }), /not a valid engagement slug/);
    assert.throws(() => engagementFile(roots.control, name, "roe.json"), /not a valid engagement slug/);
    assert.deepEqual(touched, []);
  }
  // Control: the fixture's own name is accepted by the same path.
  assert.equal((await ok()).engagement, SLUG);
  assert.equal(engagementFile(roots.control, SLUG, "roe.json"), path.join(roots.control, SLUG, "roe.json"));
  assert.throws(() => engagementFile(roots.control, SLUG, "..", "..", "x"), /leaves the engagement directory/);
});

test("an engagement that is not stored for this user is 404", async () => {
  const { io, touched } = recordingIo();
  const response = await statusResponse("nope", { findEngagement: async () => null, roots, io, fetchTool: stack });
  assert.equal(response.status, 404);
  assert.deepEqual(touched, []);
});

test("without the recon server's URL or the stack token, recon says available: false", async () => {
  const cases: [Record<string, string>, RegExp][] = [
    [{}, /^the recon server is not configured \(BUGGY_MCP_RECON_URL\)$/],
    [{ BUGGY_STACK_MCP_TOKEN: "t".repeat(32) }, /^the recon server is not configured \(BUGGY_MCP_RECON_URL\)$/],
    [{ BUGGY_MCP_RECON_URL: "http://127.0.0.1:9/mcp" }, /BUGGY_STACK_MCP_TOKEN is not set/],
    [{ BUGGY_MCP_RECON_URL: "http://127.0.0.1:9/mcp", BUGGY_STACK_MCP_TOKEN: "  " }, /BUGGY_STACK_MCP_TOKEN is not set/],
  ];
  for (const [env, expected] of cases) {
    let requests = 0;
    const fetchTool = toolFetchFromEnv(env, {
      fetchImpl: async () => {
        requests++;
        throw new Error("no request may be made");
      },
    });
    const snapshot = await ok({ fetchTool });
    assert.equal(snapshot.recon.available, false);
    assert.match((snapshot.recon as { detail: string }).detail, expected);
    assert.equal(requests, 0);
    // The sections read from disk are not affected, and the gap is named, not guessed over.
    assert.equal(snapshot.scope.available, true);
    assert.equal(snapshot.approvals.available, true);
    assert.equal(snapshot.findings.available, false);
    assert.equal(snapshot.evidence.available, false);
    assert.ok(snapshot.next.some((line) => line.startsWith("Recon state is unknown: ")));
  }
});

test("a failing or foreign recon answer is unavailable, never 'not started'", async () => {
  const thrown = await ok({
    fetchTool: async () => {
      throw new Error("boom");
    },
  });
  assert.deepEqual(thrown.recon, { available: false, detail: "recon.recon_summary failed: boom" });
  const errored = await ok({ fetchTool: async () => ({ error: "unauthorized" }) });
  assert.deepEqual(errored.recon, { available: false, detail: "unauthorized" });
  assert.deepEqual(reconFromSummary({}, NOW), {
    available: false,
    detail: "recon.recon_summary returned no run state",
  });
  // Control: a server that reports no run at all is "not started".
  const idle = reconFromSummary({ current_run: null, last_run: null, records: {} }, NOW);
  assert.ok(idle.available);
  assert.equal(idle.state, "not_started");
});

test("reconFromSummary reports a finished run with its drops and duration", () => {
  const done = reconFromSummary(
    {
      records: { url: 2 },
      current_run: null,
      last_run: { status: "completed", started_at: 100, finished_at: 190.04, scope_drops: 6 },
    },
    NOW,
  );
  assert.deepEqual(done, {
    available: true,
    state: "completed",
    stage: "",
    stages_done: [],
    started_at: 100,
    elapsed_s: 90,
    records: { url: 2 },
    scope_drops: 6,
  });
});

test("only files under the control and audit roots are read, never the secrets root", async () => {
  const { io, touched, read } = recordingIo();
  await ok({ io });
  const allowed = [
    roots.control,
    roots.audit,
    await fsp.realpath(roots.control),
    await fsp.realpath(roots.audit),
  ];
  assert.ok(read.length >= 5, "the fixture files were read");
  for (const file of touched) {
    const resolved = path.resolve(file);
    assert.ok(
      allowed.some((root) => resolved === root || resolved.startsWith(root + path.sep)),
      `touched outside the roots: ${file}`,
    );
    assert.equal(resolved.startsWith(secrets), false);
  }
});

test("a file that resolves outside its root is refused, not read", async () => {
  const outside = path.join(secrets, "requests.jsonl");
  await fsp.writeFile(outside, jsonl([request("apr-from-outside", { method: "POST", url: "https://x.test/" })]));
  const other = "link-test";
  await fsp.mkdir(path.join(roots.control, other), { recursive: true });
  await fsp.mkdir(path.join(roots.audit, other, "approvals"), { recursive: true });
  fs.symlinkSync(outside, path.join(roots.audit, other, "approvals", "requests.jsonl"));
  fs.symlinkSync(path.join(secrets, SLUG, "identities.json"), path.join(roots.control, other, "hunt-result.json"));

  const { io, read } = recordingIo();
  const snapshot = await ok({ findEngagement: async () => ({ name: other }), io });
  assert.deepEqual(snapshot.approvals, {
    available: false,
    detail: "cannot read the approval files: it resolves outside its root",
  });
  assert.deepEqual(snapshot.hunt, {
    available: false,
    detail: "cannot read hunt-result.json: it resolves outside its root",
  });
  assert.deepEqual(read, []);
  assert.equal(JSON.stringify(snapshot).includes("apr-from-outside"), false);
  assert.equal(JSON.stringify(snapshot).includes("never-read"), false);
});

test("an engagement with nothing on disk yet: missing files are stated, not invented", async () => {
  const snapshot = await ok({ findEngagement: async () => ({ name: "not-there-yet" }), fetchTool: unconfigured });
  assert.equal(snapshot.scope.available, false);
  assert.match((snapshot.scope as { detail: string }).detail, /no enforced scope \(roe\.json\)/);
  assert.deepEqual(snapshot.approvals, {
    available: true,
    total: 0,
    pending: 0,
    allowed: 0,
    denied: 0,
    other: 0,
    pending_requests: [],
  });
  assert.deepEqual(snapshot.agents, { available: true, last: null, allow: 0, refuse: 0 });
  assert.equal(snapshot.hunt.available, false);
  assert.deepEqual(snapshot.recon_report, { available: true, present: false, modified_at: null });
});

test("scopeFromDocument reads what the CLI shows and rejects a malformed document", () => {
  const base = { machine_enforcement: { mode: "warn", in_scope: ["a.test"] } };
  const scope = scopeFromDocument({ ...base, pipeline: { rate_limit_rps: 3 }, approvals: { state_changing: "not_required" } }, {
    platform: "hackerone",
    handle: "acme",
  });
  assert.ok(scope.available);
  assert.equal(scope.mode, "warn");
  assert.equal(scope.rate_limit_rps, 3);
  assert.equal(scope.sandbox_egress, "scoped");
  assert.equal(scope.approvals.state_changing, "not_required");
  assert.deepEqual(scope.program, { platform: "hackerone", handle: "acme" });

  const defaults = scopeFromDocument(base, null);
  assert.ok(defaults.available);
  assert.equal(defaults.rate_limit_rps, 10);
  // The enforced delay is a ceiling the pipeline block cannot raise.
  const capped = scopeFromDocument(
    { machine_enforcement: { min_inter_request_delay_ms: 2000 }, pipeline: { rate_limit_rps: 50 } },
    null,
  );
  assert.ok(capped.available);
  assert.equal(capped.rate_limit_rps, 1);
  assert.equal(capped.mode, "audit");

  const damaged = scopeFromDocument(base, { _invalid: "program.json is not a JSON object" });
  assert.ok(damaged.available);
  assert.equal(damaged.program?.invalid, "program.json is not a JSON object");

  for (const bad of [
    [],
    {},
    { machine_enforcement: [] },
    { machine_enforcement: { mode: "off" } },
    { machine_enforcement: { in_scope: "a.test" } },
    { machine_enforcement: { in_scope: [{ type: "host" }] } },
    { machine_enforcement: { min_inter_request_delay_ms: -1 } },
  ]) {
    assert.equal(scopeFromDocument(bad, null).available, false, JSON.stringify(bad));
  }
});

test("findingsFromResult counts by status and lists only exploit-verified findings, worst first", async () => {
  const { findings } = await ok();
  assert.ok(findings.available);
  assert.equal(findings.total, 3);
  assert.deepEqual(findings.by_status, {
    candidate: 1,
    exploit_verified: 2,
    source_verified: 0,
    inconclusive: 0,
    discarded: 0,
  });
  assert.deepEqual(findings.by_grade, { submit: 0, hold: 1, discard: 0, ungraded: 2 });
  assert.deepEqual(findings.exploit_verified, [
    { id: "F-a", title: "IDOR", severity: "high", class: "access_control" },
    { id: "F-b", title: "Low one", severity: "low", class: "xss" },
  ]);
  assert.equal(findingsFromResult({ nothing: true }).available, false);
  assert.equal(evidenceFromResult({ count: 1 }).available, false);
  const page = evidenceFromResult({ captures: [{ created_at: 5 }] });
  assert.ok(page.available);
  assert.equal(page.count_is_lower_bound, true);
});

test("nextActions says nothing about a section that is fine and names each one that is not", () => {
  const fine = {
    scope: scopeFromDocument({ machine_enforcement: { mode: "enforce" } }, null),
    recon: reconFromSummary(
      { current_run: null, last_run: { status: "completed", started_at: 1, finished_at: 2 }, records: {} },
      NOW,
    ),
    approvals: joinApprovals([request("r1", {})], [decision("r1", "allow")]),
    evidence: evidenceFromResult({ count: 3, captures: [{}] }),
    findings: findingsFromResult({ findings: [] }),
    agents: { available: true as const, last: null, allow: 0, refuse: 0 },
  };
  assert.deepEqual(nextActions("acme", fine), []);
  const gone = { available: false as const, detail: "gone" };
  assert.deepEqual(nextActions("acme", { ...fine, approvals: gone, findings: gone }), [
    "Approvals cannot be read: gone",
    "Findings cannot be read: gone",
  ]);
});

test("parseJsonl skips blank lines, malformed lines and values that are not objects", () => {
  assert.deepEqual(parseJsonl('{"a":1}\n\n  \nnope\n[1]\n"s"\n{"b":2}'), [{ a: 1 }, { b: 2 }]);
});

test("rootsFromEnv resolves the roots the approvals route uses", () => {
  assert.deepEqual(rootsFromEnv({ CONTROL_PATH: "/control", AUDIT_PATH: "/audit", HOME: "/home/op" }), {
    control: "/control",
    audit: "/audit",
  });
  assert.deepEqual(rootsFromEnv({ HOME: "/home/op" }), {
    control: "/home/op/.buggy/control",
    audit: "/home/op/.buggy/audit",
  });
});
