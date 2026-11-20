// The engagement status snapshot, assembled the way `buggy-cli status` does
// (packages/buggy/buggy/cli/status.py), from the same sources:
//
//   control root  <CONTROL_PATH>/<slug>/  roe.json, program.json,
//                                         approvals/decisions.jsonl,
//                                         hunt-result.json, recon-report.md
//   audit root    <AUDIT_PATH>/<slug>/    approvals/requests.jsonl,
//                                         roe-decisions.jsonl
//   recon and capture MCP servers         recon, evidence and findings
//
// Nothing is written and nothing is sent to a target. A section that cannot
// be read says `available: false` with the reason; it is never filled with a
// guess. Only the two roots above are read: every path is built from a
// validated engagement slug and fixed file names, and a file that resolves
// outside its root (a symlink) is refused.

import * as fsp from "fs/promises";
import * as path from "path";
import { isValidEngagementSlug } from "@/lib/engagement-slug";
import { callMcpTool, type McpCallOptions, type McpResult } from "./mcp";
import {
  BODY_PREVIEW_CHARS,
  FINDING_GRADES,
  FINDING_STATUSES,
  SEVERITIES,
  UNGRADED,
  type AgentsSection,
  type ApprovalsSection,
  type EvidenceSection,
  type FindingsSection,
  type HuntSection,
  type PendingApproval,
  type ReconReportSection,
  type ReconSection,
  type ScopeSection,
  type StatusSnapshot,
  type Unavailable,
  type VerifiedFinding,
} from "./shape";

type Row = Record<string, unknown>;

/** `fetchTool(server, tool, arguments)`: one read from a stack MCP server. */
export type ToolFetch = (server: McpServer, tool: string, args: Row) => Promise<McpResult>;
export type McpServer = "recon" | "capture";

export interface Roots {
  control: string;
  audit: string;
}

/** The file reads the snapshot makes; replaced in tests to see what is touched. */
export interface FileIo {
  realpath(file: string): Promise<string>;
  stat(file: string): Promise<{ isFile(): boolean; size: number; mtimeMs: number }>;
  readFile(file: string): Promise<string>;
}

export interface SnapshotDeps {
  roots: Roots;
  fetchTool: ToolFetch;
  /** Seconds since the epoch, as in the CLI snapshot. */
  now: number;
  io?: FileIo;
}

const RECON_NOT_STARTED = "not_started";
const RECON_RUNNING = "running";
/** `http_captures` is asked for the newest capture only. */
const CAPTURES_LIMIT = 1;
const DEFAULT_RATE_LIMIT_RPS = 10;
const ENFORCEMENT_MODES = ["audit", "warn", "enforce"];

const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_JSONL_BYTES = 16 * 1024 * 1024;
const MAX_PENDING_LISTED = 100;
const MAX_VERIFIED_LISTED = 200;
const MAX_SCOPE_ENTRIES = 500;

export const SERVER_ENV: Record<McpServer, string> = {
  recon: "BUGGY_MCP_RECON_URL",
  capture: "BUGGY_MCP_CAPTURE_URL",
};
export const TOKEN_ENV = "BUGGY_STACK_MCP_TOKEN";

const nodeIo: FileIo = {
  realpath: (file) => fsp.realpath(file),
  stat: (file) => fsp.stat(file),
  readFile: (file) => fsp.readFile(file, "utf-8"),
};

// ── small helpers ────────────────────────────────────────────────────

function unavailable(detail: string): Unavailable {
  return { available: false, detail };
}

function isRecord(value: unknown): value is Row {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function dict(value: unknown): Row {
  return isRecord(value) ? value : {};
}

/** A JSON number; `null` for anything else (booleans included). */
function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function count(value: unknown): number | null {
  const number = num(value);
  return number !== null && number >= 0 ? Math.trunc(number) : null;
}

/** Text for display: `""` for a missing value, cut to `max` characters. */
function text(value: unknown, max = 500): string {
  if (!value) return "";
  const raw = typeof value === "string" ? value : typeof value === "object" ? JSON.stringify(value) : String(value);
  return clip(raw, max).text;
}

/** Cut to `max` characters (code points, so a character is never split). */
export function clip(value: string, max: number): { text: string; truncated: boolean } {
  if (value.length <= max) return { text: value, truncated: false };
  const points = Array.from(value);
  if (points.length <= max) return { text: value, truncated: false };
  return { text: points.slice(0, max).join(""), truncated: true };
}

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    // The parser's own message quotes the file; the reason shown must not.
    throw new Error("it is not valid JSON");
  }
}

function reason(error: unknown): string {
  const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
  return code || (error instanceof Error ? error.message : String(error)).slice(0, 200);
}

// ── paths and reads ──────────────────────────────────────────────────

/**
 * The control and audit roots, resolved as the approvals route resolves them
 * (api/engagements/[id]/approvals/route.ts::workspaceFor).
 */
export function rootsFromEnv(env: Record<string, string | undefined>): Roots {
  const home = path.join(env.HOME ?? "", ".buggy");
  return {
    control: env.CONTROL_PATH ?? path.join(home, "control"),
    audit: env.AUDIT_PATH ?? path.join(home, "audit"),
  };
}

/**
 * `<root>/<slug>/<parts...>`. Throws for a name that is not an engagement
 * slug, or for a path that would leave the engagement's directory.
 */
export function engagementFile(root: string, slug: string, ...parts: string[]): string {
  if (!isValidEngagementSlug(slug)) {
    throw new Error("not a valid engagement slug");
  }
  const base = path.resolve(root, slug);
  const file = path.resolve(base, ...parts);
  if (file !== base && !file.startsWith(base + path.sep)) {
    throw new Error("the path leaves the engagement directory");
  }
  return file;
}

function isMissing(error: unknown): boolean {
  return isRecord(error) && (error.code === "ENOENT" || error.code === "ENOTDIR");
}

/**
 * The contents of `file`, or `null` when it does not exist. Throws when it
 * resolves outside `root`, is not a regular file, is too large or cannot be read.
 */
async function readContained(
  io: FileIo,
  root: string,
  file: string,
  maxBytes: number,
): Promise<{ text: string; mtimeMs: number } | null> {
  let realRoot: string;
  let real: string;
  try {
    realRoot = await io.realpath(root);
    real = await io.realpath(file);
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
  if (!real.startsWith(realRoot + path.sep)) {
    throw new Error("it resolves outside its root");
  }
  const info = await io.stat(real);
  if (!info.isFile()) throw new Error("it is not a regular file");
  if (info.size > maxBytes) throw new Error(`it is larger than ${maxBytes} bytes`);
  return { text: await io.readFile(real), mtimeMs: info.mtimeMs };
}

/** JSON objects, one per line. Blank and malformed lines are skipped. */
export function parseJsonl(raw: string): Row[] {
  const rows: Row[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const value: unknown = JSON.parse(trimmed);
      if (isRecord(value)) rows.push(value);
    } catch {
      // Skip a malformed line.
    }
  }
  return rows;
}

async function readJsonl(io: FileIo, root: string, file: string): Promise<Row[]> {
  const found = await readContained(io, root, file, MAX_JSONL_BYTES);
  return found ? parseJsonl(found.text) : [];
}

// ── scope ────────────────────────────────────────────────────────────

/** Python's `int(value)` when that is positive, else `fallback` (scope.py::_positive_int). */
function positiveInt(value: unknown, fallback: number): number {
  let number: number | null = num(value);
  if (typeof value === "string" && /^\s*[+-]?\d+\s*$/.test(value)) number = Number(value);
  if (value === true) number = 1;
  if (number === null) return fallback;
  const whole = Math.trunc(number);
  return whole > 0 ? whole : fallback;
}

function ruleTexts(field: string, entries: unknown): string[] {
  if (entries !== undefined && !Array.isArray(entries)) {
    throw new Error(`${field} must be a JSON array`);
  }
  const out: string[] = [];
  for (const entry of (entries as unknown[] | undefined) ?? []) {
    const target = isRecord(entry) ? entry.target : entry;
    if (typeof target !== "string" || !target.trim()) {
      throw new Error(`${field} entries require a nonempty target string`);
    }
    out.push(clip(target, 300).text);
  }
  return out;
}

/**
 * The scope section from a decoded `roe.json` (and `program.json`, when there is one).
 *
 * This reads the fields the CLI shows and rejects a document whose shape is
 * wrong. It is not the enforcement parser (buggy_core `parse_roe_document`):
 * target syntax (CIDR, URL forms) and time windows are not re-validated here.
 */
export function scopeFromDocument(document: unknown, program: unknown): ScopeSection | Unavailable {
  if (!isRecord(document)) return unavailable("the enforced scope is invalid: roe.json must be a JSON object");
  const block = document.machine_enforcement;
  if (block === undefined) {
    return unavailable("the enforced scope is invalid: roe.json has no machine_enforcement block");
  }
  if (!isRecord(block)) {
    return unavailable("the enforced scope is invalid: machine_enforcement must be a JSON object");
  }
  const mode = String(block.mode ?? "audit").toLowerCase();
  if (!ENFORCEMENT_MODES.includes(mode)) {
    return unavailable("the enforced scope is invalid: the mode must be audit, warn or enforce");
  }
  const delay = block.min_inter_request_delay_ms ?? 0;
  if (typeof delay !== "number" || !Number.isInteger(delay) || delay < 0) {
    return unavailable(
      "the enforced scope is invalid: min_inter_request_delay_ms must be a nonnegative integer",
    );
  }
  let inScope: string[];
  let outOfScope: string[];
  try {
    inScope = ruleTexts("in_scope", block.in_scope);
    outOfScope = ruleTexts("out_of_scope", block.out_of_scope);
  } catch (error) {
    return unavailable(`the enforced scope is invalid: ${reason(error)}`);
  }

  // The pipeline's request rate: its own setting, never above what the
  // enforced delay between requests allows (PipelineLimits.from_roe).
  let rate = positiveInt(dict(document.pipeline).rate_limit_rps, DEFAULT_RATE_LIMIT_RPS);
  if (delay > 0) rate = Math.min(rate, Math.max(1, Math.floor(1000 / delay)));

  const approvals = dict(document.approvals);
  let programInfo: ScopeSection["program"] = null;
  if (isRecord(program)) {
    programInfo =
      "_invalid" in program
        ? { platform: "", handle: "", invalid: text(program._invalid, 300) }
        : { platform: text(program.platform, 100), handle: text(program.handle, 200) };
  }
  return {
    available: true,
    mode,
    in_scope: inScope.slice(0, MAX_SCOPE_ENTRIES),
    out_of_scope: outOfScope.slice(0, MAX_SCOPE_ENTRIES),
    rate_limit_rps: rate,
    sandbox_egress: String(block.sandbox_egress ?? "").toLowerCase() === "blocked" ? "blocked" : "scoped",
    approvals: {
      state_changing: text(approvals.state_changing ?? "required", 60),
      report_submission: text(approvals.report_submission ?? "not_required", 60),
    },
    program: programInfo,
  };
}

async function scopeSection(io: FileIo, roots: Roots, slug: string): Promise<ScopeSection | Unavailable> {
  let document: unknown;
  try {
    const found = await readContained(io, roots.control, engagementFile(roots.control, slug, "roe.json"), MAX_JSON_BYTES);
    if (!found) return unavailable(`no enforced scope (roe.json) for ${slug}`);
    document = parseJson(found.text);
  } catch (error) {
    return unavailable(`cannot read the enforced scope (roe.json): ${reason(error)}`);
  }
  let program: unknown = null;
  try {
    const found = await readContained(
      io,
      roots.control,
      engagementFile(roots.control, slug, "program.json"),
      MAX_JSON_BYTES,
    );
    if (found) {
      const parsed = parseJson(found.text);
      program = isRecord(parsed) ? parsed : { _invalid: "program.json is not a JSON object" };
    }
  } catch (error) {
    // A damaged program record must not read as "not a program engagement".
    program = { _invalid: `cannot read program.json: ${reason(error)}` };
  }
  return scopeFromDocument(document, program);
}

// ── recon, evidence, findings (MCP servers) ──────────────────────────

async function remote(
  fetchTool: ToolFetch,
  server: McpServer,
  tool: string,
  args: Row,
): Promise<{ result: Row; failed: null } | { result: null; failed: Unavailable }> {
  let result: unknown;
  try {
    result = await fetchTool(server, tool, args);
  } catch (error) {
    return { result: null, failed: unavailable(`${server}.${tool} failed: ${reason(error)}`) };
  }
  if (!isRecord(result)) {
    return { result: null, failed: unavailable(`${server}.${tool} returned something that is not an object`) };
  }
  if (result.error) {
    return { result: null, failed: unavailable(text(result.error, 400)) };
  }
  return { result, failed: null };
}

/** Pipeline state from a `recon_summary` result (status.py::_recon_section). */
export function reconFromSummary(summary: Row, now: number): ReconSection | Unavailable {
  if (!("current_run" in summary) || !("last_run" in summary)) {
    // An empty or foreign result must not read as "recon has not started".
    return unavailable("recon.recon_summary returned no run state");
  }
  const current = dict(summary.current_run);
  const last = dict(summary.last_run);
  const records: Record<string, number> = {};
  for (const name of Object.keys(dict(summary.records)).sort()) {
    const value = count(dict(summary.records)[name]);
    if (value !== null) records[clip(name, 60).text] = value;
  }
  const section: ReconSection = {
    available: true,
    state: RECON_NOT_STARTED,
    stage: "",
    stages_done: [],
    started_at: null,
    elapsed_s: null,
    records,
    scope_drops: null,
  };
  const round1 = (seconds: number) => Math.round(Math.max(0, seconds) * 10) / 10;
  if (Object.keys(current).length > 0) {
    const started = num(current.started_at);
    section.state = RECON_RUNNING;
    section.stage = text(current.stage, 60);
    section.stages_done = Array.isArray(current.stages_done)
      ? current.stages_done.slice(0, 50).map((stage) => text(stage, 60))
      : [];
    section.started_at = started;
    section.elapsed_s = started === null ? null : round1(now - started);
  } else if (Object.keys(last).length > 0) {
    const started = num(last.started_at);
    const finished = num(last.finished_at);
    section.state = text(last.status, 60) || "unknown";
    section.started_at = started;
    section.elapsed_s = started === null || finished === null ? null : round1(finished - started);
    section.scope_drops = count(last.scope_drops);
  }
  return section;
}

/** Capture count and the time of the newest capture (status.py::_evidence_section). */
export function evidenceFromResult(result: Row): EvidenceSection | Unavailable {
  const captures = result.captures;
  if (!Array.isArray(captures)) return unavailable("capture.http_captures returned no capture list");
  const reported = count(result.count);
  const total = reported === null ? captures.length : Math.max(reported, captures.length);
  const newest = dict(captures[0]);
  return {
    available: true,
    count: total,
    count_is_lower_bound: total === captures.length && captures.length >= CAPTURES_LIMIT,
    last_capture_at: num(newest.created_at),
  };
}

function severityRank(severity: string): number {
  const index = (SEVERITIES as readonly string[]).indexOf(severity);
  return index === -1 ? SEVERITIES.length : index;
}

/** Counts by status and grade, and the exploit-verified findings (status.py::_findings_section). */
export function findingsFromResult(result: Row): FindingsSection | Unavailable {
  const rows = "findings" in result ? result.findings : result.result;
  if (!Array.isArray(rows)) return unavailable("capture.findings_list returned no finding list");
  const findings = rows.filter(isRecord);
  const byStatus: Record<string, number> = Object.fromEntries(FINDING_STATUSES.map((s) => [s, 0]));
  const byGrade: Record<string, number> = Object.fromEntries([...FINDING_GRADES, UNGRADED].map((g) => [g, 0]));
  const verified: VerifiedFinding[] = [];
  for (const finding of findings) {
    const status = text(finding.status, 40) || "unknown";
    byStatus[status] = (byStatus[status] ?? 0) + 1;
    const grade = text(finding.grade, 40) || UNGRADED;
    byGrade[grade] = (byGrade[grade] ?? 0) + 1;
    if (status === "exploit_verified") {
      verified.push({
        id: text(finding.id, 80),
        title: text(finding.title, 300),
        severity: text(finding.severity, 40),
        class: text(finding.class, 80),
      });
    }
  }
  verified.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  return {
    available: true,
    total: findings.length,
    by_status: byStatus,
    by_grade: byGrade,
    exploit_verified: verified.slice(0, MAX_VERIFIED_LISTED),
  };
}

// ── approvals ────────────────────────────────────────────────────────

function pendingItem(requestId: string, row: Row): PendingApproval {
  const item: PendingApproval = {
    request_id: clip(requestId, 120).text,
    tool_name: text(row.tool_name, 120),
    reason: text(row.reason, 500),
    agent_name: text(row.agent_name, 120),
    created_at: num(row.created_at),
  };
  const args = dict(row.tool_args_redacted);
  if (args.method) item.method = text(args.method, 20);
  if (args.url) item.url = text(args.url, 2000);

  // The body is shown as a short preview only, whatever the request file holds.
  const body = args.body_preview ?? args.body;
  if (body !== undefined && body !== null && body !== "") {
    const raw = typeof body === "string" ? body : JSON.stringify(body);
    const preview = clip(raw, BODY_PREVIEW_CHARS);
    item.body_preview = preview.text;
    item.body_truncated = preview.truncated;
  }
  if (!item.url && Object.keys(args).length > 0) {
    // Not an HTTP request: the operator still has to see what is being asked for.
    item.args_preview = clip(JSON.stringify(args), BODY_PREVIEW_CHARS).text;
  }
  return item;
}

function requestId(row: Row): string {
  const id = row.request_id;
  return typeof id === "string" ? id : typeof id === "number" ? String(id) : "";
}

/**
 * Requests (audit root) joined with the operator's decisions (control root).
 *
 * A request is pending while no decision names it. The first line for a
 * request id is the request; the last decision for it is the one that counts,
 * as in the capture gateway and in `buggy-cli status`.
 */
export function joinApprovals(requestRows: Row[], decisionRows: Row[]): ApprovalsSection {
  const requests = new Map<string, Row>();
  for (const row of requestRows) {
    const id = requestId(row);
    if (id && !requests.has(id)) requests.set(id, row);
  }
  const actions = new Map<string, string>();
  for (const row of decisionRows) {
    const id = requestId(row);
    if (id) actions.set(id, String(row.action ?? "").toLowerCase());
  }
  const counts = { pending: 0, allowed: 0, denied: 0, other: 0 };
  const pending: PendingApproval[] = [];
  for (const [id, row] of requests) {
    const action = actions.get(id);
    if (action === undefined) {
      counts.pending += 1;
      if (pending.length < MAX_PENDING_LISTED) pending.push(pendingItem(id, row));
    } else if (action === "allow") counts.allowed += 1;
    else if (action === "deny") counts.denied += 1;
    else counts.other += 1;
  }
  return { available: true, total: requests.size, ...counts, pending_requests: pending };
}

async function approvalsSection(io: FileIo, roots: Roots, slug: string): Promise<ApprovalsSection | Unavailable> {
  try {
    const [requests, decisions] = await Promise.all([
      readJsonl(io, roots.audit, engagementFile(roots.audit, slug, "approvals", "requests.jsonl")),
      readJsonl(io, roots.control, engagementFile(roots.control, slug, "approvals", "decisions.jsonl")),
    ]);
    return joinApprovals(requests, decisions);
  } catch (error) {
    return unavailable(`cannot read the approval files: ${reason(error)}`);
  }
}

// ── agents, hunt result, recon report ────────────────────────────────

/** The guardrail's decision ledger: its last line and how many calls it allowed or refused. */
export function agentsFromRows(rows: Row[]): AgentsSection {
  let allow = 0;
  let refuse = 0;
  for (const row of rows) {
    if (row.decision === "allow") allow += 1;
    else if (row.decision === "refuse") refuse += 1;
  }
  const last = rows.at(-1);
  return {
    available: true,
    last: last
      ? {
          at: num(last.ts),
          tool: text(last.tool, 120),
          decision: text(last.decision, 40),
          event: text(last.event, 120),
        }
      : null,
    allow,
    refuse,
  };
}

async function agentsSection(io: FileIo, roots: Roots, slug: string): Promise<AgentsSection | Unavailable> {
  try {
    return agentsFromRows(
      await readJsonl(io, roots.audit, engagementFile(roots.audit, slug, "roe-decisions.jsonl")),
    );
  } catch (error) {
    return unavailable(`cannot read the decision ledger (roe-decisions.jsonl): ${reason(error)}`);
  }
}

function counts(value: unknown, keys?: readonly string[]): Record<string, number> {
  const source = dict(value);
  const out: Record<string, number> = {};
  for (const key of keys ?? Object.keys(source).sort()) {
    const number = count(source[key]);
    if (keys) out[key] = number ?? 0;
    else if (number !== null) out[clip(key, 60).text] = number;
  }
  return out;
}

/** `hunt-result.json` reduced to the keys `buggy hunt` documents (cli/hunt.py::build_result). */
export function huntFromDocument(document: unknown): HuntSection | Unavailable {
  if (!isRecord(document)) return unavailable("hunt-result.json is not a JSON object");
  const recon = dict(document.recon);
  const findings = dict(document.findings);
  const agent = dict(document.agent);
  return {
    available: true,
    engagement: text(document.engagement, 80),
    finished_at: num(document.finished_at),
    recon: {
      state: text(recon.state, 60) || "unknown",
      records: counts(recon.records),
      scope_drops: count(recon.scope_drops),
    },
    issues: counts(document.issues, SEVERITIES),
    findings: {
      available: findings.available === true,
      exploit_verified: { ...counts(findings.exploit_verified, SEVERITIES), ...counts(findings.exploit_verified) },
      inconclusive: count(findings.inconclusive) ?? 0,
      candidates: count(findings.candidates) ?? 0,
    },
    approvals_pending: count(document.approvals_pending) ?? 0,
    agent: { ran: agent.ran === true, error: agent.error ? text(agent.error, 500) : null },
    complete: document.complete === true,
  };
}

async function huntSection(io: FileIo, roots: Roots, slug: string): Promise<HuntSection | Unavailable> {
  try {
    const found = await readContained(
      io,
      roots.control,
      engagementFile(roots.control, slug, "hunt-result.json"),
      MAX_JSON_BYTES,
    );
    if (!found) return unavailable("no hunt has finished for this engagement (no hunt-result.json)");
    return huntFromDocument(parseJson(found.text));
  } catch (error) {
    return unavailable(`cannot read hunt-result.json: ${reason(error)}`);
  }
}

/** Whether `recon-report.md` exists. The report itself is not read. */
async function reconReportSection(io: FileIo, roots: Roots, slug: string): Promise<ReconReportSection | Unavailable> {
  try {
    const realRoot = await io.realpath(roots.control);
    const real = await io.realpath(engagementFile(roots.control, slug, "recon-report.md"));
    if (!real.startsWith(realRoot + path.sep)) throw new Error("it resolves outside its root");
    const info = await io.stat(real);
    return { available: true, present: info.isFile(), modified_at: info.isFile() ? info.mtimeMs / 1000 : null };
  } catch (error) {
    if (isMissing(error)) return { available: true, present: false, modified_at: null };
    return unavailable(`cannot check recon-report.md: ${reason(error)}`);
  }
}

// ── next actions ─────────────────────────────────────────────────────

function plural(n: number, singular: string, many: string): string {
  return `${n} ${n === 1 ? singular : many}`;
}

type Sections = Pick<StatusSnapshot, "scope" | "recon" | "approvals" | "evidence" | "findings" | "agents">;

/** Plain-language next steps, most urgent first: the same lines `buggy-cli status` prints. */
export function nextActions(engagement: string, sections: Sections): string[] {
  const { scope, recon, approvals, evidence, findings, agents } = sections;
  const hints: string[] = [];

  if (!scope.available) {
    hints.push(`The enforced scope cannot be used (${scope.detail}): buggy-cli scope show ${engagement}`);
  } else if (scope.program?.invalid) {
    hints.push(
      `The program record is damaged (${scope.program.invalid}): import it again with buggy-cli scope import`,
    );
  }

  if (approvals.available) {
    if (approvals.pending) {
      const waits = approvals.pending === 1 ? "request waits" : "requests wait";
      hints.push(`${approvals.pending} ${waits} for approval: buggy-cli approvals list ${engagement}`);
    }
  } else {
    hints.push(`Approvals cannot be read: ${approvals.detail}`);
  }

  if (recon.available) {
    if (recon.state === RECON_NOT_STARTED) {
      if (scope.available && scope.mode !== "enforce") {
        hints.push(
          "Recon will not start: the pipeline runs only in 'enforce' mode and the " +
            `scope is in '${scope.mode}' mode`,
        );
      } else {
        hints.push(
          "Recon has not started: the pipeline worker starts it when it sees the " +
            `enforced scope (watch with buggy-cli status ${engagement} --follow)`,
        );
      }
    } else if (recon.state === RECON_RUNNING) {
      hints.push(
        `Recon is running (stage: ${recon.stage || "starting"}): buggy-cli status ${engagement} --follow`,
      );
    } else if (recon.state === "failed") {
      hints.push(
        "Recon failed: read the pipeline service log, then run it again with " +
          `buggy-cli pipeline run ${engagement}`,
      );
    } else if (recon.state === "interrupted") {
      hints.push(
        "Recon was interrupted: the pipeline worker resumes it on its own " +
          `(watch with buggy-cli status ${engagement} --follow)`,
      );
    } else if (
      recon.state === "completed" &&
      // Only when all three places an agent leaves a trace were read and are empty.
      agents.available &&
      agents.last === null &&
      approvals.available &&
      !approvals.total &&
      evidence.available &&
      !evidence.count
    ) {
      hints.push(
        "Recon is complete and nothing shows that an agent has run (no guardrail " +
          "decision, capture or approval request): " +
          `buggy hunt <target> --engagement-name ${engagement} continues from this recon`,
      );
    }
  } else {
    hints.push(`Recon state is unknown: ${recon.detail}`);
  }

  if (findings.available) {
    const verified = findings.exploit_verified.length;
    if (verified) {
      hints.push(`${plural(verified, "finding is", "findings are")} exploit-verified and ready for review`);
    }
    const unverified = (findings.by_status.candidate ?? 0) + (findings.by_status.inconclusive ?? 0);
    if (unverified) {
      hints.push(
        `${plural(unverified, "finding is", "findings are")} not verified yet ` +
          "(candidate or inconclusive) and do not count as findings",
      );
    }
  } else {
    hints.push(`Findings cannot be read: ${findings.detail}`);
  }

  if (!evidence.available) hints.push(`Evidence cannot be read: ${evidence.detail}`);
  if (!agents.available) hints.push(`Agent activity cannot be read: ${agents.detail}`);
  return hints;
}

// ── the snapshot ─────────────────────────────────────────────────────

/**
 * The reader for the stack's MCP servers. A server is asked only when both
 * its URL variable and the stack token are set; otherwise the read is an
 * `{ error }` result and its section says `available: false`.
 */
export function toolFetchFromEnv(
  env: Record<string, string | undefined>,
  options: McpCallOptions = {},
): ToolFetch {
  return async (server, tool, args) => {
    const url = (env[SERVER_ENV[server]] ?? "").trim();
    const token = (env[TOKEN_ENV] ?? "").trim();
    // The first message is the Python client's, word for word (pipeline/mcp_client.py).
    if (!url) return { error: `the ${server} server is not configured (${SERVER_ENV[server]})` };
    if (!token) return { error: `the ${server} server cannot be asked (${TOKEN_ENV} is not set)` };
    return callMcpTool(url, token, tool, args, options);
  };
}

/** Everything known about the engagement `slug` right now. Throws for a name that is not a slug. */
export async function buildSnapshot(slug: string, deps: SnapshotDeps): Promise<StatusSnapshot> {
  if (!isValidEngagementSlug(slug)) {
    throw new Error("not a valid engagement slug");
  }
  const io = deps.io ?? nodeIo;
  const { roots, fetchTool, now } = deps;

  const [scope, reconRead, approvals, evidenceRead, findingsRead, agents, hunt, reconReport] = await Promise.all([
    scopeSection(io, roots, slug),
    remote(fetchTool, "recon", "recon_summary", { engagement: slug }),
    approvalsSection(io, roots, slug),
    remote(fetchTool, "capture", "http_captures", { engagement: slug, limit: CAPTURES_LIMIT }),
    remote(fetchTool, "capture", "findings_list", { engagement: slug }),
    agentsSection(io, roots, slug),
    huntSection(io, roots, slug),
    reconReportSection(io, roots, slug),
  ]);
  const sections: Sections = {
    scope,
    recon: reconRead.failed ?? reconFromSummary(reconRead.result, now),
    approvals,
    evidence: evidenceRead.failed ?? evidenceFromResult(evidenceRead.result),
    findings: findingsRead.failed ?? findingsFromResult(findingsRead.result),
    agents,
  };
  return {
    engagement: slug,
    generated_at: now,
    ...sections,
    next: nextActions(slug, sections),
    hunt,
    recon_report: reconReport,
  };
}

// ── the route's logic, without the framework ─────────────────────────

export interface StatusDeps extends Omit<SnapshotDeps, "now"> {
  /** The stored engagement for this id and the signed-in user, or `null`. */
  findEngagement(id: string): Promise<{ name: string } | null>;
  now?: number;
}

export interface StatusResponse {
  status: number;
  body: StatusSnapshot | { error: string };
}

/**
 * GET /api/engagements/[id]/status. The stored engagement name becomes a
 * directory name under the roots, so it is validated with the slug rule the
 * other engagement routes use before any path is built: a stored name is
 * never trusted.
 */
export async function statusResponse(id: string, deps: StatusDeps): Promise<StatusResponse> {
  const engagement = await deps.findEngagement(id);
  if (!engagement) {
    return { status: 404, body: { error: "Not found" } };
  }
  if (!isValidEngagementSlug(engagement.name)) {
    return { status: 400, body: { error: "Engagement name is not a valid workspace slug" } };
  }
  const snapshot = await buildSnapshot(engagement.name, {
    roots: deps.roots,
    fetchTool: deps.fetchTool,
    io: deps.io,
    now: deps.now ?? Date.now() / 1000,
  });
  return { status: 200, body: snapshot };
}
