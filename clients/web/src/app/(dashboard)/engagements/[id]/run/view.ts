// Pure view logic for the run page: what each panel shows for a snapshot.
// No React and no browser APIs, so it is tested with `npm test`.

import {
  RECON_STAGES,
  type ReconSection,
  type Unavailable,
} from "@/app/api/engagements/[id]/status/shape";

export type StepState = "done" | "current" | "pending" | "unknown";

export interface StageStep {
  name: string;
  state: StepState;
}

/**
 * The seven pipeline stages with their state.
 *
 * The recon server names the current stage and the finished ones only while a
 * run is in progress. A completed run has finished every stage; for a run
 * that failed or was interrupted the stage it reached is not reported, so the
 * steps are "unknown" rather than guessed.
 */
export function stageSteps(recon: ReconSection | Unavailable): StageStep[] {
  const all = (state: StepState): StageStep[] => RECON_STAGES.map((name) => ({ name, state }));
  if (!recon.available) return all("unknown");
  if (recon.state === "not_started") return all("pending");
  if (recon.state === "completed") return all("done");
  if (recon.state !== "running") return all("unknown");
  const done = new Set(recon.stages_done);
  return RECON_STAGES.map((name) => ({
    name,
    state: name === recon.stage ? "current" : done.has(name) ? "done" : "pending",
  }));
}

/** Record types by count, largest first, then by name. */
export function sortedRecords(records: Record<string, number>): [string, number][] {
  return Object.entries(records).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

/** `m:ss`, or `h:mm:ss` from one hour on; "unknown" without a number. */
export function formatDuration(seconds: number | null | undefined): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "unknown";
  const whole = Math.floor(seconds);
  const hours = Math.floor(whole / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  const secs = String(whole % 60).padStart(2, "0");
  return hours ? `${hours}:${String(minutes).padStart(2, "0")}:${secs}` : `${minutes}:${secs}`;
}

export type OperatorAction = "allow" | "deny";

/**
 * The body the existing approvals API (POST /api/engagements/[id]/approvals)
 * takes for one decision on one request. There is no form of it that names
 * more than one request: every decision is a separate act of the operator.
 */
export function decisionBody(requestId: string, action: OperatorAction) {
  if (action !== "allow" && action !== "deny") {
    throw new Error("the action must be allow or deny");
  }
  if (!requestId) {
    throw new Error("a decision names one request");
  }
  return { request_id: requestId, action, operator_note: "" };
}
