import { test } from "node:test";
import assert from "node:assert/strict";
import { decisionBody, formatDuration, sortedRecords, stageSteps } from "./view";
import { RECON_STAGES, type ReconSection } from "@/app/api/engagements/[id]/status/shape";

function recon(overrides: Partial<ReconSection>): ReconSection {
  return {
    available: true,
    state: "not_started",
    stage: "",
    stages_done: [],
    started_at: null,
    elapsed_s: null,
    records: {},
    scope_drops: null,
    ...overrides,
  };
}

test("stageSteps lists the seven stages in pipeline order", () => {
  const steps = stageSteps(recon({}));
  assert.deepEqual(
    steps.map((s) => s.name),
    ["enumerate", "dns", "live", "fingerprint", "urls", "apispec", "issues"],
  );
  assert.equal(RECON_STAGES.length, 7);
});

test("a running recon highlights exactly the current stage", () => {
  const steps = stageSteps(recon({ state: "running", stage: "live", stages_done: ["enumerate", "dns"] }));
  assert.deepEqual(
    steps.map((s) => s.state),
    ["done", "done", "current", "pending", "pending", "pending", "pending"],
  );
  // Before the first stage is named, nothing is highlighted.
  const starting = stageSteps(recon({ state: "running" }));
  assert.ok(starting.every((s) => s.state === "pending"));
});

test("stage states are not guessed when the run does not report them", () => {
  assert.ok(stageSteps(recon({ state: "not_started" })).every((s) => s.state === "pending"));
  assert.ok(stageSteps(recon({ state: "completed" })).every((s) => s.state === "done"));
  for (const state of ["failed", "interrupted", "unknown"]) {
    assert.ok(stageSteps(recon({ state })).every((s) => s.state === "unknown"), state);
  }
  assert.ok(stageSteps({ available: false, detail: "no server" }).every((s) => s.state === "unknown"));
});

test("sortedRecords and formatDuration", () => {
  assert.deepEqual(sortedRecords({ url: 2, dns_record: 9, port: 2 }), [
    ["dns_record", 9],
    ["port", 2],
    ["url", 2],
  ]);
  assert.equal(formatDuration(0), "0:00");
  assert.equal(formatDuration(61.9), "1:01");
  assert.equal(formatDuration(3725), "1:02:05");
  assert.equal(formatDuration(null), "unknown");
  assert.equal(formatDuration(-1), "unknown");
});

test("a decision names one request and is allow or deny, nothing else", () => {
  assert.deepEqual(decisionBody("apr-1", "allow"), { request_id: "apr-1", action: "allow", operator_note: "" });
  assert.deepEqual(decisionBody("apr-2", "deny"), { request_id: "apr-2", action: "deny", operator_note: "" });
  assert.throws(() => decisionBody("apr-1", "redirect" as never), /allow or deny/);
  assert.throws(() => decisionBody("", "allow"), /one request/);
});
