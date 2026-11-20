// The engagement status snapshot: what GET /api/engagements/[id]/status returns.
//
// It has the top-level keys of `buggy-cli status --json`
// (packages/buggy/buggy/cli/status.py::snapshot) so the CLI and the run page
// show the same thing, plus `hunt` and `recon_report`, which the CLI prints
// from files of their own.
//
// This module has no Node imports: the run page (a client component) imports
// its types and constants.

/** Pipeline stage order (packages/buggy/buggy/pipeline/pipeline.py::STAGES). */
export const RECON_STAGES = [
  "enumerate",
  "dns",
  "live",
  "fingerprint",
  "urls",
  "apispec",
  "issues",
] as const;

export const FINDING_STATUSES = [
  "candidate",
  "exploit_verified",
  "source_verified",
  "inconclusive",
  "discarded",
] as const;

export const FINDING_GRADES = ["submit", "hold", "discard"] as const;
export const UNGRADED = "ungraded";
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** The most a pending approval ever shows of a request body or of tool arguments. */
export const BODY_PREVIEW_CHARS = 200;

/** A section that could not be read. It is never filled with a guess. */
export interface Unavailable {
  available: false;
  detail: string;
}

export interface ScopeSection {
  available: true;
  mode: string;
  in_scope: string[];
  out_of_scope: string[];
  rate_limit_rps: number;
  sandbox_egress: string;
  approvals: { state_changing: string; report_submission: string };
  program: { platform: string; handle: string; invalid?: string } | null;
}

export interface ReconSection {
  available: true;
  state: string;
  stage: string;
  stages_done: string[];
  started_at: number | null;
  elapsed_s: number | null;
  records: Record<string, number>;
  scope_drops: number | null;
}

export interface PendingApproval {
  request_id: string;
  tool_name: string;
  reason: string;
  agent_name: string;
  created_at: number | null;
  method?: string;
  url?: string;
  /** At most BODY_PREVIEW_CHARS characters of the request body. */
  body_preview?: string;
  /** True when the stored body was longer than the preview. */
  body_truncated?: boolean;
  /** For a tool call that is not an HTTP request: its redacted arguments, cut the same way. */
  args_preview?: string;
}

export interface ApprovalsSection {
  available: true;
  total: number;
  pending: number;
  allowed: number;
  denied: number;
  other: number;
  pending_requests: PendingApproval[];
}

export interface EvidenceSection {
  available: true;
  count: number;
  count_is_lower_bound: boolean;
  last_capture_at: number | null;
}

export interface VerifiedFinding {
  id: string;
  title: string;
  severity: string;
  class: string;
}

export interface FindingsSection {
  available: true;
  total: number;
  by_status: Record<string, number>;
  by_grade: Record<string, number>;
  exploit_verified: VerifiedFinding[];
}

export interface AgentsSection {
  available: true;
  last: { at: number | null; tool: string; decision: string; event: string } | null;
  allow: number;
  refuse: number;
}

/** `hunt-result.json`, as `buggy hunt` wrote it at the end of its last run. */
export interface HuntSection {
  available: true;
  engagement: string;
  finished_at: number | null;
  recon: { state: string; records: Record<string, number>; scope_drops: number | null };
  issues: Record<string, number>;
  findings: {
    available: boolean;
    exploit_verified: Record<string, number>;
    inconclusive: number;
    candidates: number;
  };
  approvals_pending: number;
  agent: { ran: boolean; error: string | null };
  complete: boolean;
}

export interface ReconReportSection {
  available: true;
  present: boolean;
  modified_at: number | null;
}

export interface StatusSnapshot {
  engagement: string;
  generated_at: number;
  scope: ScopeSection | Unavailable;
  recon: ReconSection | Unavailable;
  approvals: ApprovalsSection | Unavailable;
  evidence: EvidenceSection | Unavailable;
  findings: FindingsSection | Unavailable;
  agents: AgentsSection | Unavailable;
  next: string[];
  hunt: HuntSection | Unavailable;
  recon_report: ReconReportSection | Unavailable;
}
