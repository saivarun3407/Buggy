"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Check, FileWarning, Loader2, Radar, ShieldAlert, ShieldCheck, Target, X } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  FINDING_STATUSES,
  SEVERITIES,
  type ApprovalsSection,
  type FindingsSection,
  type HuntSection,
  type PendingApproval,
  type ReconReportSection,
  type ReconSection,
  type ScopeSection,
  type StatusSnapshot,
  type Unavailable,
} from "@/app/api/engagements/[id]/status/shape";
import { decisionBody, formatDuration, sortedRecords, stageSteps, type OperatorAction } from "./view";

const POLL_INTERVAL_MS = 5000;
const SHOWN_SCOPE_ENTRIES = 8;

const severityBadge: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300",
  high: "bg-orange-500/20 text-orange-300",
  medium: "bg-yellow-500/20 text-yellow-300",
  low: "bg-blue-500/20 text-blue-300",
  info: "bg-slate-500/20 text-slate-300",
};

function clock(at: number | null | undefined): string {
  return typeof at === "number" ? new Date(at * 1000).toLocaleTimeString() : "unknown";
}

function label(value: string): string {
  return value.replace(/_/g, " ");
}

function UnavailableNote({ section }: { section: Unavailable }) {
  return (
    <p className="rounded-md border border-border/50 bg-muted/30 p-3 text-xs text-muted-foreground">
      Unavailable: {section.detail}
    </p>
  );
}

function Fact({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-xs">
      <dt className="w-32 shrink-0 text-muted-foreground">{name}</dt>
      <dd className="min-w-0 flex-1 break-words">{children}</dd>
    </div>
  );
}

function Panel({
  title,
  icon: Icon,
  aside,
  children,
}: {
  title: string;
  icon: typeof Target;
  aside?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="h-4 w-4 text-muted-foreground" />
          {title}
        </CardTitle>
        {aside}
      </CardHeader>
      <CardContent className="space-y-3">{children}</CardContent>
    </Card>
  );
}

function ScopeList({ entries }: { entries: string[] }) {
  if (entries.length === 0) return <span className="text-muted-foreground">(nothing)</span>;
  return (
    <span className="font-mono">
      {entries.slice(0, SHOWN_SCOPE_ENTRIES).join(", ")}
      {entries.length > SHOWN_SCOPE_ENTRIES && (
        <span className="font-sans text-muted-foreground"> (+{entries.length - SHOWN_SCOPE_ENTRIES} more)</span>
      )}
    </span>
  );
}

function ScopePanel({ scope }: { scope: ScopeSection | Unavailable }) {
  return (
    <Panel
      title="Scope"
      icon={Target}
      aside={scope.available ? <Badge variant="outline">{scope.mode} mode</Badge> : undefined}
    >
      {!scope.available ? (
        <UnavailableNote section={scope} />
      ) : (
        <dl className="space-y-1.5">
          <Fact name="In scope">
            <ScopeList entries={scope.in_scope} />
          </Fact>
          {scope.out_of_scope.length > 0 && (
            <Fact name="Out of scope">
              <ScopeList entries={scope.out_of_scope} />
            </Fact>
          )}
          <Fact name="Rate">{scope.rate_limit_rps} req/s</Fact>
          <Fact name="Sandbox network">{scope.sandbox_egress}</Fact>
          <Fact name="Approvals">
            state-changing requests: {label(scope.approvals.state_changing)} · report submission:{" "}
            {label(scope.approvals.report_submission)}
          </Fact>
          {scope.program && (
            <Fact name="Program">
              {scope.program.invalid
                ? `record damaged (${scope.program.invalid})`
                : `${scope.program.platform}/${scope.program.handle}`}
            </Fact>
          )}
        </dl>
      )}
    </Panel>
  );
}

function RecordCounts({ records }: { records: Record<string, number> }) {
  const rows = sortedRecords(records);
  if (rows.length === 0) return <span className="text-muted-foreground">none</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {rows.map(([name, value]) => (
        <Badge key={name} variant="secondary" className="font-mono text-[11px]">
          {label(name)} {value}
        </Badge>
      ))}
    </span>
  );
}

function ReconPanel({
  recon,
  hunt,
  report,
}: {
  recon: ReconSection | Unavailable;
  hunt: HuntSection | Unavailable;
  report: ReconReportSection | Unavailable;
}) {
  const steps = stageSteps(recon);
  return (
    <Panel
      title="Recon"
      icon={Radar}
      aside={recon.available ? <Badge variant="outline">{label(recon.state)}</Badge> : undefined}
    >
      <ol className="flex flex-wrap gap-2" aria-label="Recon stages">
        {steps.map((step, index) => (
          <li
            key={step.name}
            aria-current={step.state === "current" ? "step" : undefined}
            className={cn(
              "flex items-center gap-1.5 rounded-lg border px-2 py-1 text-xs",
              step.state === "current" && "border-primary bg-primary/10 font-medium text-foreground",
              step.state === "done" && "border-emerald-500/30 text-emerald-300",
              step.state === "pending" && "border-border/50 text-muted-foreground",
              step.state === "unknown" && "border-dashed border-border/50 text-muted-foreground",
            )}
          >
            {step.state === "done" ? (
              <Check className="h-3 w-3" />
            ) : step.state === "current" ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <span className="font-mono text-[10px]">{index + 1}</span>
            )}
            {step.name}
          </li>
        ))}
      </ol>

      {!recon.available ? (
        <UnavailableNote section={recon} />
      ) : (
        <dl className="space-y-1.5">
          {recon.started_at !== null && <Fact name="Started">{clock(recon.started_at)}</Fact>}
          {recon.elapsed_s !== null && <Fact name="Elapsed">{formatDuration(recon.elapsed_s)}</Fact>}
          <Fact name="Records">
            <RecordCounts records={recon.records} />
          </Fact>
          {recon.scope_drops !== null && (
            <Fact name="Dropped">{recon.scope_drops} candidates were out of scope</Fact>
          )}
        </dl>
      )}

      {hunt.available && (
        <dl className="space-y-1.5 border-t border-border/50 pt-3">
          <Fact name="Last hunt run">
            {hunt.complete ? "complete" : "incomplete"} · finished {clock(hunt.finished_at)} · recon{" "}
            {label(hunt.recon.state)}
            {hunt.agent.error ? ` · agent error: ${hunt.agent.error}` : hunt.agent.ran ? " · agent ran" : ""}
          </Fact>
          {!recon.available && (
            <Fact name="Records then">
              <RecordCounts records={hunt.recon.records} />
            </Fact>
          )}
          <Fact name="Known issues">
            {SEVERITIES.filter((severity) => hunt.issues[severity]).map((severity) => (
              <Badge key={severity} className={cn("mr-1.5 text-[11px]", severityBadge[severity])}>
                {hunt.issues[severity]} {severity}
              </Badge>
            ))}
            {SEVERITIES.every((severity) => !hunt.issues[severity]) && (
              <span className="text-muted-foreground">none</span>
            )}
          </Fact>
        </dl>
      )}
      {report.available && report.present && (
        <p className="text-xs text-muted-foreground">
          Recon report written {clock(report.modified_at)}: recon-report.md in the engagement&apos;s control
          directory.
        </p>
      )}
    </Panel>
  );
}

function ApprovalRow({
  request,
  busy,
  disabled,
  error,
  onDecide,
}: {
  request: PendingApproval;
  busy: OperatorAction | null;
  disabled: boolean;
  error: string | null;
  onDecide: (action: OperatorAction) => void;
}) {
  return (
    <li className="space-y-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        {request.method && (
          <Badge variant="outline" className="font-mono">
            {request.method}
          </Badge>
        )}
        <code className="min-w-0 flex-1 break-all font-mono">{request.url ?? request.tool_name}</code>
      </div>
      <p className="text-muted-foreground">
        {request.tool_name}
        {request.agent_name ? ` · ${request.agent_name}` : ""}
        {request.created_at !== null ? ` · asked ${clock(request.created_at)}` : ""} ·{" "}
        <span className="font-mono">{request.request_id}</span>
      </p>
      {request.reason && <p>{request.reason}</p>}
      {request.body_preview !== undefined && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Body preview{request.body_truncated ? " (cut)" : ""}
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border/50 bg-background/40 p-2 font-mono text-[11px]">
            {request.body_preview}
          </pre>
        </div>
      )}
      {request.args_preview !== undefined && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Arguments (redacted, preview)
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border/50 bg-background/40 p-2 font-mono text-[11px]">
            {request.args_preview}
          </pre>
        </div>
      )}
      {error && <p className="text-destructive">{error}</p>}
      <div className="flex gap-2">
        <Button
          type="button"
          size="sm"
          onClick={() => onDecide("allow")}
          disabled={disabled}
          className="bg-emerald-600 text-white hover:bg-emerald-500"
        >
          {busy === "allow" ? <Loader2 className="animate-spin" /> : <Check />}
          Allow
        </Button>
        <Button type="button" size="sm" variant="destructive" onClick={() => onDecide("deny")} disabled={disabled}>
          {busy === "deny" ? <Loader2 className="animate-spin" /> : <X />}
          Deny
        </Button>
      </div>
    </li>
  );
}

function ApprovalsPanel({
  approvals,
  engagementId,
  onDecided,
}: {
  approvals: ApprovalsSection | Unavailable;
  engagementId: string;
  onDecided: () => void;
}) {
  // One decision at a time, each started by a click on that request's own button.
  const [submitting, setSubmitting] = useState<{ id: string; action: OperatorAction } | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  // Requests answered here, hidden until the next snapshot no longer lists them.
  const [answered, setAnswered] = useState<Set<string>>(new Set());

  async function decide(requestId: string, action: OperatorAction) {
    if (submitting) return;
    setSubmitting({ id: requestId, action });
    setErrors((prev) => ({ ...prev, [requestId]: "" }));
    try {
      const res = await fetch(`/api/engagements/${engagementId}/approvals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(decisionBody(requestId, action)),
      });
      if (res.ok || res.status === 409) {
        // 409: it was already decided elsewhere (the CLI, another tab).
        setAnswered((prev) => new Set(prev).add(requestId));
        onDecided();
      } else {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        setErrors((prev) => ({ ...prev, [requestId]: data?.error ?? "The decision was not recorded" }));
      }
    } catch {
      setErrors((prev) => ({ ...prev, [requestId]: "Network error: the decision was not recorded" }));
    } finally {
      setSubmitting(null);
    }
  }

  const pending = approvals.available
    ? approvals.pending_requests.filter((request) => !answered.has(request.request_id))
    : [];

  return (
    <Panel
      title="Approvals"
      icon={ShieldAlert}
      aside={
        approvals.available ? (
          <span className="text-xs text-muted-foreground">
            {approvals.pending} pending · {approvals.allowed} allowed · {approvals.denied} denied
            {approvals.other ? ` · ${approvals.other} other` : ""}
          </span>
        ) : undefined
      }
    >
      {!approvals.available ? (
        <UnavailableNote section={approvals} />
      ) : pending.length === 0 ? (
        <p className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
          <ShieldCheck className="h-4 w-4" /> No request is waiting for approval
        </p>
      ) : (
        <>
          <ul className="space-y-2">
            {pending.map((request) => (
              <ApprovalRow
                key={request.request_id}
                request={request}
                busy={submitting?.id === request.request_id ? submitting.action : null}
                disabled={submitting !== null}
                error={errors[request.request_id] || null}
                onDecide={(action) => decide(request.request_id, action)}
              />
            ))}
          </ul>
          {approvals.pending > approvals.pending_requests.length && (
            <p className="text-xs text-muted-foreground">
              +{approvals.pending - approvals.pending_requests.length} more pending, shown once these are answered
            </p>
          )}
        </>
      )}
    </Panel>
  );
}

function FindingsPanel({
  findings,
  hunt,
}: {
  findings: FindingsSection | Unavailable;
  hunt: HuntSection | Unavailable;
}) {
  return (
    <Panel
      title="Findings"
      icon={FileWarning}
      aside={
        findings.available ? (
          <span className="text-xs text-muted-foreground">{findings.total} recorded</span>
        ) : undefined
      }
    >
      {!findings.available ? (
        <>
          <UnavailableNote section={findings} />
          {hunt.available && hunt.findings.available && (
            <dl className="space-y-1.5">
              <Fact name="At the last hunt run">
                {Object.entries(hunt.findings.exploit_verified)
                  .filter(([, value]) => value > 0)
                  .map(([severity, value]) => `${value} ${severity}`)
                  .join(", ") || "no"}{" "}
                exploit-verified · {hunt.findings.inconclusive} inconclusive · {hunt.findings.candidates}{" "}
                candidates (finished {clock(hunt.finished_at)})
              </Fact>
            </dl>
          )}
        </>
      ) : (
        <>
          <div className="flex flex-wrap gap-1.5">
            {[
              ...FINDING_STATUSES,
              ...Object.keys(findings.by_status).filter(
                (status) => !(FINDING_STATUSES as readonly string[]).includes(status),
              ),
            ].map((status) => (
              <Badge
                key={status}
                variant={status === "exploit_verified" ? "default" : "secondary"}
                className="text-[11px]"
              >
                {findings.by_status[status] ?? 0} {label(status)}
              </Badge>
            ))}
          </div>
          {findings.exploit_verified.length === 0 ? (
            <p className="py-4 text-sm text-muted-foreground">
              No exploit-verified finding yet. Only exploit-verified findings count as findings.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>ID</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.exploit_verified.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <Badge className={cn("text-[11px]", severityBadge[finding.severity] ?? "bg-zinc-500/20")}>
                        {finding.severity || "unknown"}
                      </Badge>
                    </TableCell>
                    <TableCell className="whitespace-normal">{finding.title}</TableCell>
                    <TableCell className="text-muted-foreground">{label(finding.class)}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{finding.id}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </Panel>
  );
}

export default function EngagementRunPage() {
  const params = useParams();
  const id = params.id as string;
  const [snapshot, setSnapshot] = useState<StatusSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (inFlight.current) return;
      inFlight.current = true;
      try {
        const res = await fetch(`/api/engagements/${id}/status`, { signal, cache: "no-store" });
        const data = (await res.json().catch(() => null)) as StatusSnapshot | { error?: string } | null;
        if (!res.ok || !data || !("engagement" in data)) {
          setError((data && "error" in data && data.error) || `The status could not be loaded (HTTP ${res.status})`);
          return;
        }
        setSnapshot(data);
        setError(null);
      } catch {
        if (!signal?.aborted) setError("The status could not be loaded (network error)");
      } finally {
        inFlight.current = false;
      }
    },
    [id],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    const interval = setInterval(() => {
      if (!document.hidden) load(controller.signal);
    }, POLL_INTERVAL_MS);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [load]);

  if (!snapshot) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Run</h1>
        {error ? (
          <p className="text-sm text-destructive">{error}</p>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-48 w-full" />
            ))}
          </div>
        )}
      </div>
    );
  }

  const { evidence, agents } = snapshot;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Run</h1>
        <p className="text-sm text-muted-foreground">
          {snapshot.engagement} · status at {clock(snapshot.generated_at)}
          {error ? " · " : ""}
          {error && <span className="text-destructive">not refreshed: {error}</span>}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          Evidence:{" "}
          {evidence.available
            ? `${evidence.count_is_lower_bound ? "at least " : ""}${evidence.count} captures` +
              (evidence.last_capture_at !== null ? `, last ${clock(evidence.last_capture_at)}` : "")
            : `unavailable (${evidence.detail})`}
          {" · "}Agents:{" "}
          {agents.available
            ? agents.last
              ? `last ${clock(agents.last.at)} ${agents.last.tool} ${agents.last.decision} · ` +
                `${agents.allow} allowed, ${agents.refuse} refused`
              : "no activity recorded"
            : `unavailable (${agents.detail})`}
        </p>
      </div>

      {snapshot.next.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">What to do now</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {snapshot.next.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <ScopePanel scope={snapshot.scope} />
        <ReconPanel recon={snapshot.recon} hunt={snapshot.hunt} report={snapshot.recon_report} />
        <ApprovalsPanel approvals={snapshot.approvals} engagementId={id} onDecided={() => void load()} />
        <FindingsPanel findings={snapshot.findings} hunt={snapshot.hunt} />
      </div>
    </div>
  );
}
