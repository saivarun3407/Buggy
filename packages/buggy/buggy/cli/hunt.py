"""``buggy-cli hunt`` — give it a URL you are authorized to test; it does the rest.

    buggy-cli hunt https://app.example.com
    buggy-cli hunt app.example.com --include-subdomains
    buggy-cli hunt https://app.example.com --instruction "test accounts: a@x / b@x"

What happens, in order:

1. **Scope.** The enforced scope is written for exactly the hosts you named
   (``--include-subdomains`` adds every subdomain, ``--scope`` adds patterns).
   Enforce mode, a conservative rate limit, operator approval before any
   state-changing request, and no network path from the agent's shell to the
   target: requests go through the evidence gateway, where they are recorded.
2. **Recon.** The deterministic pipeline (pinned tools, no LLM) maps hosts,
   services, endpoints, API specifications and known issues.
3. **Report.** A recon report is written from those records, still with no
   LLM: known issues by severity with fixes, and what to test next.
4. **Agents.** With a model configured, the agents read the recon data, pick
   what to test, run the deterministic probes and chain what they find.
   Skipped with ``--no-agent`` or when no run can be started.

Nothing is sent to a host outside the scope, and nothing state-changing is
sent without your approval (``buggy-cli approvals list <engagement>``).
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from buggy.cli import _paths
from buggy.cli.engage import (
    _host_from_target,
    _load_scope_file,
    _split_patterns,
    _stream_kickoff,
    _validate_scope_entries,
    _write_plan_bundle,
)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INTERNAL = 3

#: Polite for a target you named yourself; program imports default lower.
DEFAULT_RPS = 10
MAX_RPS = 50
RECON_POLL_SECONDS = 5.0
#: Record types the report reads, and how many of each at most.
REPORT_TYPES: dict[str, int] = {
    "vulnerability": 1000,
    "secret": 200,
    "http_service": 300,
    "technology": 600,
    "api_spec": 100,
    "graphql": 50,
    "api_operation": 1000,
    "endpoint": 1500,
    "url": 1500,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli hunt",
        description="Test a target you are authorized to test, starting from a URL.",
    )
    p.add_argument("targets", nargs="+", metavar="TARGET", help="URL, host, IP or CIDR.")
    p.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Extra in-scope pattern: host, *.domain (one label), **.domain (any depth), IP, CIDR.",
    )
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    p.add_argument(
        "--scope-file",
        type=Path,
        default=None,
        help='Scope file: JSON {"in_scope": [...], "out_of_scope": [...]} or one pattern per line.',
    )
    p.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Also put every subdomain of each target host in scope.",
    )
    p.add_argument("--instruction", default="", help="Focus and test-account notes for the agents.")
    p.add_argument(
        "--rps", type=int, default=DEFAULT_RPS, help="Requests per second (default 10, max 50)."
    )
    p.add_argument(
        "--port-scan", action="store_true", help="Scan the top 100 ports (off by default)."
    )
    p.add_argument(
        "--crawl-exclude",
        action="append",
        default=[],
        metavar="REGEX",
        help="URL pattern the crawler must not follow (logout and delete links are always skipped).",
    )
    p.add_argument(
        "--internal",
        action="store_true",
        help="The target is on a private network (allow private addresses that are in scope).",
    )
    p.add_argument(
        "--lab",
        action="store_true",
        help="A training target you own: no approval holds, private addresses allowed, "
        "agent shell may reach the target.",
    )
    p.add_argument(
        "--allow-sandbox-network",
        action="store_true",
        help="Let the agent's shell reach in-scope targets directly. Requests sent that way are "
        "not held for approval.",
    )
    p.add_argument("--no-agent", action="store_true", help="Recon and report only; no LLM.")
    p.add_argument(
        "--force-agent",
        action="store_true",
        help="Start the agent run even when no model provider is detected in the environment.",
    )
    p.add_argument("--no-recon-wait", action="store_true", help="Do not wait for the pipeline.")
    p.add_argument("--recon-timeout", type=int, default=3600)
    p.add_argument("--yes", "-y", action="store_true", help="I am authorized; do not prompt.")
    p.add_argument("--engagement-name", default=None)
    p.add_argument("--plan-only", action="store_true", help="Write the scope and stop.")
    p.add_argument("--mode", choices=("audit", "warn", "enforce"), default="enforce")
    p.add_argument("--workspace-root", type=Path, default=None)
    p.add_argument("--control-root", type=Path, default=None)
    p.add_argument(
        "--langgraph-url", default=os.environ.get("BUGGY_API_URL", "http://localhost:2024")
    )
    p.add_argument("--assistant", default="")
    p.add_argument("--timeout", type=int, default=4 * 3600)
    p.add_argument("--non-interactive", "-n", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


# ── scope ────────────────────────────────────────────────────────────


def _scope_host(target: str) -> str:
    """The scope rule for a target: its host, without scheme, port or path."""
    raw = target.strip().lower()
    if _is_ip(raw):  # an address or a CIDR is its own scope rule
        return raw
    token = _host_from_target(target).lower().rstrip(".")
    if token.startswith("["):  # [v6]:port
        return token.split("]", 1)[0].lstrip("[")
    try:
        ipaddress.ip_network(token, strict=False)
        return token
    except ValueError:
        pass
    host, _, port = token.rpartition(":")
    return host if host and port.isdigit() else token


def _seed_url(target: str) -> str | None:
    return target.strip() if re.match(r"^https?://", target.strip(), re.IGNORECASE) else None


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_network(host, strict=False).is_private
    except ValueError:
        return False


def _slug(hosts: list[str], supplied: str | None) -> str:
    if supplied:
        return supplied
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = re.sub(r"[^a-z0-9]+", "-", hosts[0].lower()).strip("-")[:40] or "target"
    return f"hunt-{base}-{stamp}"


def build_scope(args: argparse.Namespace) -> dict[str, Any]:
    """Everything the engagement's ``roe.json`` will say, from the command line."""
    targets = [t.strip() for t in args.targets if t.strip()]
    hosts = list(dict.fromkeys(_scope_host(t) for t in targets))
    in_scope = list(hosts)
    if args.include_subdomains:
        in_scope += [f"**.{h}" for h in hosts if not _is_ip(h)]
    in_scope += _split_patterns(args.scope)
    out_of_scope = _split_patterns(args.exclude)
    if args.scope_file:
        file_in, file_out = _load_scope_file(args.scope_file)
        in_scope += file_in
        out_of_scope += file_out
    in_scope = list(dict.fromkeys(in_scope))
    out_of_scope = list(dict.fromkeys(out_of_scope))

    rps = max(1, min(int(args.rps), MAX_RPS))
    lab = bool(args.lab)
    sandbox_blocked = not (lab or args.allow_sandbox_network)
    private = lab or args.internal or any(_is_private(h) for h in hosts)
    return {
        "targets": targets,
        "hosts": hosts,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "rps": rps,
        "enforcement_extra": {
            "min_inter_request_delay_ms": max(1, 1000 // rps),
            "max_concurrent_connections": min(5, rps),
            "sandbox_egress": "blocked" if sandbox_blocked else "scoped",
        },
        "document_extra": {
            "authorization": "Operator confirmed authorization on the command line.",
            "pipeline": {
                "rate_limit_rps": rps,
                "concurrency": min(5, rps),
                "port_scan": bool(args.port_scan),
                "nuclei_severities": ["info", "low", "medium", "high", "critical"],
                "crawl_exclude": list(args.crawl_exclude),
                "seed_urls": [u for u in (_seed_url(t) for t in targets) if u],
            },
            "approvals": {"state_changing": "not_required" if lab else "required"},
            "network": {"allow_private_targets": private},
        },
    }


_PATTERN_RE = re.compile(
    r"^(?:\*{1,2}\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$"
)


def pattern_errors(patterns: list[str]) -> list[str]:
    """Scope patterns that are neither an address, a network, nor a hostname form."""
    return [
        f"{pattern!r} is not a host, *.domain, **.domain, IP or CIDR"
        for pattern in patterns
        if not _is_ip(pattern) and not _PATTERN_RE.match(pattern.lower())
    ]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False
    return True


def _confirm(scope: dict[str, Any], assume_yes: bool) -> bool:
    print("You are about to test:", file=sys.stderr)
    for pattern in scope["in_scope"]:
        print(f"  {pattern}", file=sys.stderr)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(
            "error: confirm that you are authorized to test these targets by re-running with --yes",
            file=sys.stderr,
        )
        return False
    answer = input("Are you authorized to test these targets? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _describe(scope: dict[str, Any], mode: str) -> list[str]:
    extra, doc = scope["enforcement_extra"], scope["document_extra"]
    lines = [
        f"  mode            {mode}",
        f"  in scope        {', '.join(scope['in_scope'])}",
        f"  rate limit      {scope['rps']} requests/second",
        "  approvals       "
        + (
            "none (lab)"
            if doc["approvals"]["state_changing"] == "not_required"
            else "every state-changing request waits for you"
        ),
        "  agent shell     "
        + (
            "no network path to the target (gateway, browser and pipeline only)"
            if extra["sandbox_egress"] == "blocked"
            else "can reach in-scope targets directly"
        ),
        f"  port scan       {'top 100 ports' if doc['pipeline']['port_scan'] else 'off'}",
    ]
    if scope["out_of_scope"]:
        lines.insert(2, f"  out of scope    {', '.join(scope['out_of_scope'])}")
    return lines


# ── recon ────────────────────────────────────────────────────────────


def _recon(tool: str, engagement: str, **arguments: Any) -> dict[str, Any]:
    # The framework-free client: this command also runs from the slim pipeline
    # image (lite stack), where the agent-side ``buggy.tools`` does not exist.
    from buggy.pipeline.mcp_client import call_mcp_sync  # noqa: PLC0415

    return call_mcp_sync("recon", tool, {"engagement": engagement, **arguments})


def recon_available() -> bool:
    from buggy.pipeline.mcp_client import server_configured  # noqa: PLC0415

    return server_configured("recon")


STAGE_LABELS = {
    "enumerate": "finding hosts",
    "dns": "resolving names",
    "live": "probing services",
    "fingerprint": "fingerprinting",
    "urls": "mapping URLs and endpoints",
    "apispec": "reading API specifications",
    "issues": "checking for known issues (the slow stage at a polite request rate)",
}


def wait_for_recon(
    engagement: str,
    *,
    timeout: float,
    since: float = 0.0,
    poll: float = RECON_POLL_SECONDS,
    quiet: bool = False,
    sleep: Any = time.sleep,
    clock: Any = time.monotonic,
) -> dict[str, Any]:
    """Block until the pipeline has finished a run that started after ``since``.

    Returns the final ``recon_summary`` (with ``timed_out`` set when the wait
    gave up). The pipeline worker starts on its own when it sees a new scope;
    this only watches, and says which stage is running.
    """
    started = clock()
    deadline = started + timeout
    last_line = ""
    last_print = started
    while True:
        summary = _recon("recon_summary", engagement)
        if summary.get("error"):
            return summary
        current = summary.get("current_run") or {}
        last = summary.get("last_run") or {}
        counts = summary.get("records") or {}
        total = sum(int(v) for v in counts.values())
        finished = bool(last) and not current and float(last.get("started_at") or 0) >= since - 5
        if current:
            stage = str(current.get("stage") or "starting")
            line = f"  recon: {STAGE_LABELS.get(stage, stage)}"
        elif finished:
            line = f"  recon: {last.get('status')}"
        else:
            line = "  recon: waiting for the pipeline to pick up the scope"
        now = clock()
        if not quiet and (line != last_line or now - last_print >= 60):
            elapsed = int(now - started)
            print(f"{line} [{elapsed // 60}:{elapsed % 60:02d}, {total} records]", file=sys.stderr)
            last_line, last_print = line, now
        if finished:
            return summary
        if now >= deadline:
            return {**summary, "timed_out": True}
        sleep(poll)


def collect_records(engagement: str) -> dict[str, list[dict[str, Any]]]:
    """Recon records by type, paged through the read-only recon server."""
    out: dict[str, list[dict[str, Any]]] = {}
    for record_type, cap in REPORT_TYPES.items():
        rows: list[dict[str, Any]] = []
        offset = 0
        while len(rows) < cap:
            page = _recon(
                "recon_query", engagement, record_type=record_type, limit=200, offset=offset
            )
            batch = page.get("records") or []
            rows.extend(r for r in batch if isinstance(r, dict))
            if not page.get("truncated") or page.get("next_offset") is None:
                break
            offset = int(page["next_offset"])
        out[record_type] = rows[:cap]
    return out


def _host_path(path: Path) -> str:
    """How the operator finds a control-root file: inside the operator container the
    root is /control, which is ``$BUGGY_HOME/control`` (default ``~/.buggy/control``) on the host."""
    text = str(path)
    if text.startswith("/control/"):
        return f"~/.buggy/control/{text[len('/control/') :]}  (in the container: {text})"
    return text


def write_report(
    control: Path, engagement: str, scope: dict[str, Any], summary: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    from buggy.pipeline.report import group_issues, rank_candidates, render_report  # noqa: PLC0415

    records = collect_records(engagement)
    text = render_report(engagement, summary, records, scope=scope["in_scope"])
    directory = control / engagement
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "recon-report.md"
    path.write_text(text, encoding="utf-8")
    issues = group_issues(records.get("vulnerability", []))
    digest = {
        "issues": {
            severity: sum(1 for i in issues if i["severity"] == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        },
        "services": len(records.get("http_service", [])),
        "candidates": len(rank_candidates(records)),
        "secrets": len(records.get("secret", [])),
    }
    return path, digest


# ── agents ───────────────────────────────────────────────────────────

_PLACEHOLDER_KEY = re.compile(r"^(your-|sk-buggy-|changeme|<)", re.IGNORECASE)


def model_configured(env: dict[str, str] | None = None) -> bool:
    """Whether any model provider is set up, judged from the environment.

    True for a provider API key that is not a template placeholder, a
    subscription login toggle (``BUGGY_AUTH_*``), or a local Ollama endpoint.
    This only saves a doomed run from waiting on its timeout; the model
    gateway remains the authority.
    """
    source = os.environ if env is None else env
    for name, value in source.items():
        text = (value or "").strip()
        if not text:
            continue
        if (
            name.endswith("_API_KEY")
            and not name.startswith("LITELLM")
            and not _PLACEHOLDER_KEY.match(text)
        ):
            return True
        if name.startswith("BUGGY_AUTH_") and text.lower() in {"1", "true", "yes", "on"}:
            return True
        if name in ("OLLAMA_API_BASE", "OLLAMA_BASE_URL", "OLLAMA_HOST"):
            return True
    return False


def kickoff_text(slug: str, scope: dict[str, Any], *, recon_done: bool, instruction: str) -> str:
    blocked = scope["enforcement_extra"]["sandbox_egress"] == "blocked"
    parts = [
        f"Begin authorized engagement '{slug}'. Targets: {', '.join(scope['targets'])}.",
        "The scope is already enforced (plan/roe.json mirrors it); do not interview the operator "
        "for scope. Call scope_show first.",
        (
            "Recon is already done by the deterministic pipeline: read it with recon_summary and "
            "recon_query (services, endpoints, API operations, GraphQL, known issues). Do not "
            "re-enumerate or re-scan."
            if recon_done
            else "The recon pipeline may still be running: read what exists with recon_summary "
            "and recon_query before doing any enumeration yourself."
        ),
        "Spend your effort on what needs judgement: choose what to test, run the deterministic "
        "probes (probe_list, probe_run) on the best candidates, and chain confirmed results into "
        "impact. Priorities: access control and IDOR, authentication and session, SSRF, business "
        "logic, API flaws, GraphQL.",
        (
            "The sandbox has no network path to the target. Send every request with http_send, "
            "probe_run or the browser_* tools; a state-changing request returns APPROVAL_REQUIRED "
            "until the operator allows it, so batch those and keep working on read-only checks."
            if blocked
            else "Prefer http_send, probe_run and browser_* for anything that counts as evidence."
        ),
        "Record each finding with report_record_finding, citing capture_ids and a remediation. "
        "No denial of service, no social engineering, no data beyond what proves the issue.",
    ]
    if instruction.strip():
        parts.append(f"Operator instruction: {instruction.strip()}")
    return " ".join(parts)


# ── entry ────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911, PLR0912, PLR0915
    args = _build_parser().parse_args(argv)
    try:
        scope = build_scope(args)
    except RuntimeError as exc:  # unreadable or malformed --scope-file
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if not scope["targets"]:
        print("error: name at least one target", file=sys.stderr)
        return EXIT_CONFIG
    errors = pattern_errors([*scope["in_scope"], *scope["out_of_scope"]])
    errors += _validate_scope_entries(scope["in_scope"], scope["out_of_scope"])
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return EXIT_CONFIG
    if not _confirm(scope, args.yes):
        print("not started; nothing was written or sent", file=sys.stderr)
        return EXIT_CONFIG

    slug = _slug(scope["hosts"], args.engagement_name)
    started_at = time.time()
    workspace = _paths.workspace_root(args.workspace_root)
    control = _paths.control_root(args.control_root)
    try:
        _write_plan_bundle(
            root=workspace,
            slug=slug,
            targets=scope["targets"],
            in_scope=scope["in_scope"],
            out_of_scope=scope["out_of_scope"],
            mode=args.mode,
            forbidden_commands=[],
            instruction=args.instruction,
            control_root=control,
            enforcement_extra=scope["enforcement_extra"],
            document_extra=scope["document_extra"],
            generated_by="buggy-cli hunt",
        )
    except OSError as exc:
        print(
            f"error: cannot write the scope: {exc}\n"
            "The enforced scope lives under the operator-controlled root. Run this on the host, "
            "or with `docker compose --profile operator run --rm operator buggy-cli hunt ...`.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    print(f"\n[1/4] scope enforced for engagement {slug}", file=sys.stderr)
    for line in _describe(scope, args.mode):
        print(line, file=sys.stderr)
    if args.plan_only:
        print("--plan-only: scope written, nothing started", file=sys.stderr)
        return EXIT_OK

    recon_done = False
    if args.mode != "enforce":
        print("\n[2/4] recon skipped: the pipeline only runs in enforce mode", file=sys.stderr)
    elif not recon_available():
        print(
            "\n[2/4] recon not watched: this shell cannot reach the recon server "
            "(BUGGY_MCP_RECON_URL). The pipeline service still runs on its own.",
            file=sys.stderr,
        )
    elif args.no_recon_wait:
        print("\n[2/4] recon started in the background (--no-recon-wait)", file=sys.stderr)
    else:
        print("\n[2/4] recon: deterministic pipeline, no LLM", file=sys.stderr)
        summary = wait_for_recon(
            slug,
            timeout=float(args.recon_timeout),
            since=started_at,
            quiet=args.non_interactive,
        )
        if summary.get("error"):
            print(f"  recon unavailable: {summary['error']}", file=sys.stderr)
        else:
            recon_done = not summary.get("timed_out")
            if summary.get("timed_out"):
                print("  recon is still running; continuing with what exists", file=sys.stderr)
            try:
                path, digest = write_report(control, slug, scope, summary)
            except OSError as exc:
                print(f"  could not write the report: {exc}", file=sys.stderr)
            else:
                issues = ", ".join(f"{n} {s}" for s, n in digest["issues"].items() if n) or "none"
                print("\n[3/4] recon report (no LLM)", file=sys.stderr)
                print(f"  live services    {digest['services']}", file=sys.stderr)
                print(f"  known issues     {issues}", file=sys.stderr)
                print(f"  exposed secrets  {digest['secrets']}", file=sys.stderr)
                print(f"  test candidates  {digest['candidates']}", file=sys.stderr)
                print(f"  report           {_host_path(path)}", file=sys.stderr)
                if args.non_interactive:
                    print(json.dumps({"type": "recon_report", "path": str(path), **digest}))

    if args.no_agent:
        print("\n[4/4] agents skipped (--no-agent)", file=sys.stderr)
        return EXIT_OK
    if not args.force_agent and not model_configured():
        print(
            "\n[4/4] agents skipped: no model is configured. Run `buggy onboard` to add one, "
            f"then `buggy hunt ... --engagement-name {slug}` to continue from this recon. "
            "(--force-agent starts the run anyway.)",
            file=sys.stderr,
        )
        return EXIT_OK

    print(
        "\n[4/4] agents: choosing what to test, running probes, chaining findings", file=sys.stderr
    )
    try:
        result = _stream_kickoff(
            langgraph_url=args.langgraph_url,
            assistant=args.assistant or os.getenv("BUGGY_LANGGRAPH_ASSISTANT", "buggy"),
            engagement_name=slug,
            kickoff=kickoff_text(slug, scope, recon_done=recon_done, instruction=args.instruction),
            timeout_seconds=args.timeout,
            non_interactive=args.non_interactive,
        )
    except Exception as exc:  # noqa: BLE001 - recon and the report already stand on their own
        print(
            f"  the agent run did not complete: {type(exc).__name__}: {str(exc)[:300]}\n"
            + (
                "  Recon and the report above are complete. "
                if recon_done
                else "  Recon continues in the pipeline service. "
            )
            + "Check that a model is configured (`buggy onboard`) and that the langgraph "
            f"service is healthy, then re-run with --engagement-name {slug} to continue.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL

    findings = sorted((workspace / slug).glob("findings/FIND-*.md"))
    print(f"\ndone: {slug} ({result.get('event_count', 0)} agent events)", file=sys.stderr)
    print(
        f"  findings         {len(findings)} under {workspace / slug / 'findings'}", file=sys.stderr
    )
    print(f"  approvals        buggy-cli approvals list {slug}", file=sys.stderr)
    print(f"  audit ledger     buggy-cli audit {slug}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
