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

Running it again. With ``--engagement-name`` of an engagement that already
has an enforced scope, the scope this command line would write is compared
with the stored one. Equal: nothing is rewritten, nothing is asked, the run
continues from the recon that exists (``resuming <name>``). Different: the
difference is printed field by field and the stored scope is replaced only
after a confirmation (``--yes`` counts as one); otherwise the command stops
with exit code 2 and nothing on disk changes. ``--resume NAME`` takes the
targets and options from the stored scope, so it needs nothing else; options
given next to it replace the stored ones (and a changed scope is confirmed as
above).

Every run ends by writing ``<control>/<engagement>/hunt-result.json`` and by
exiting with a code a pipeline can gate on: see ``--help``.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
import tempfile
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
EXIT_INCOMPLETE = 3
#: The name this code had before the exit codes were documented.
EXIT_INTERNAL = EXIT_INCOMPLETE
EXIT_FINDINGS = 10

EXIT_CODES_HELP = """\
exit codes:
  0   the run is complete and nothing is at or above the --fail-on threshold
      (without --fail-on, findings never fail the run)
  10  the run is complete and something is at or above --fail-on: an
      exploit-verified finding, or with --fail-on-issues also a known issue
      from the recon report
  3   the run is incomplete: recon timed out or did not complete, the agent
      run failed, or the result file could not be written
  2   usage or configuration error, including a scope change that was not
      confirmed (nothing is changed on disk)

Every run that gets past the scope step writes
<control-root>/<engagement>/hunt-result.json with the same information.
"""

#: Most severe first; the order ``--fail-on`` thresholds are read in.
SEVERITIES = ("critical", "high", "medium", "low", "info")
RESULT_FILE = "hunt-result.json"
#: The blocks of ``roe.json`` that decide what may be sent where. A re-run
#: whose blocks equal the stored ones is a resume; any difference needs a yes.
COMPARED_BLOCKS = ("machine_enforcement", "pipeline", "approvals", "network")
#: ``recon.state`` in the result file. A watched run is complete only as
#: ``completed``; ``timed_out`` and any other final status (``failed``,
#: ``interrupted``) make the run incomplete.
RECON_COMPLETED = "completed"
RECON_TIMED_OUT = "timed_out"
#: States in which this command did not watch a pipeline run to its end: the
#: pipeline does not run in this mode (``skipped``), no recon server is
#: configured (``not_watched``), ``--no-recon-wait`` (``background``), or the
#: server could not be read (``unavailable``). They are reported, not failed.
RECON_NOT_WATCHED = frozenset({"skipped", "not_watched", "background", "unavailable"})
#: Boolean options kept in the stored scope (``hunt.flags``) for ``--resume``.
RESUME_FLAGS = (
    "include_subdomains",
    "port_scan",
    "internal",
    "lab",
    "allow_sandbox_network",
    "no_agent",
    "force_agent",
    "no_recon_wait",
    "fail_on_issues",
)

#: Polite for a target you named yourself; program imports default lower.
DEFAULT_RPS = 10
MAX_RPS = 50
MODES = ("audit", "warn", "enforce")
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
    "parameter": 1500,
    "js_finding": 500,
    "endpoint": 1500,
    "url": 1500,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli hunt",
        description="Test a target you are authorized to test, starting from a URL.",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="URL, host, IP or CIDR. At least one, unless --resume is given.",
    )
    p.add_argument(
        "--resume",
        default=None,
        metavar="NAME",
        help="Continue engagement NAME with the targets and options stored in its enforced "
        "scope. Options given with it replace the stored ones.",
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help="Exit 10 when an exploit-verified finding is at or above this severity "
        "(critical, high, medium, low, info). Default: findings never fail the run.",
    )
    p.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="With --fail-on: known issues from the recon report count too.",
    )
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
        "--finalize",
        action="store_true",
        help="With --resume: an agent outside this command (Claude Code) has finished. "
        "Rebuild the result and the reports from the findings store; run nothing.",
    )
    p.add_argument(
        "--agent-runner",
        default="",
        help="With --finalize: the name of the agent that ran (recorded in the result).",
    )
    p.add_argument(
        "--no-probes",
        action="store_true",
        help="Do not run the automatic read-only probe sweep after recon.",
    )
    p.add_argument(
        "--state-probe-budget",
        type=int,
        default=None,
        help="Most state-changing probe runs planned per run (default 15; 0 plans none). "
        "Each one waits for your approval.",
    )
    p.add_argument(
        "--probe-budget",
        type=int,
        default=None,
        help="Most probe runs the automatic sweep makes (default 40; 0 turns it off).",
    )
    p.add_argument(
        "--force-agent",
        action="store_true",
        help="Start the agent run even when no model provider is detected in the environment.",
    )
    p.add_argument("--no-recon-wait", action="store_true", help="Do not wait for the pipeline.")
    p.add_argument("--recon-timeout", type=int, default=3600)
    p.add_argument("--yes", "-y", action="store_true", help="I am authorized; do not prompt.")
    p.add_argument(
        "--engagement-name",
        default=None,
        help="Name of the engagement. Naming one that exists resumes it when the scope is "
        "unchanged, and asks before replacing a scope that differs.",
    )
    p.add_argument("--plan-only", action="store_true", help="Write the scope and stop.")
    p.add_argument("--mode", choices=MODES, default="enforce")
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


# ── resume ───────────────────────────────────────────────────────────

_ABSENT: Any = object()


def requested_blocks(scope: dict[str, Any], mode: str) -> dict[str, Any]:
    """The compared blocks of the ``roe.json`` this command line would write."""
    extra = scope["document_extra"]
    return {
        "machine_enforcement": {
            "mode": mode,
            "in_scope": list(scope["in_scope"]),
            "out_of_scope": list(scope["out_of_scope"]),
            "forbidden_command_patterns": [],
            **scope["enforcement_extra"],
        },
        **{name: extra[name] for name in COMPARED_BLOCKS if name in extra},
    }


def _shown(value: Any) -> str:
    if value is _ABSENT:
        return "(not set)"
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _field_diff(name: str, stored: Any, requested: Any) -> list[str]:
    if stored == requested:
        return []
    if isinstance(stored, list) and isinstance(requested, list):
        lines = [f"  {name}: + {_shown(item)}" for item in requested if item not in stored]
        lines += [f"  {name}: - {_shown(item)}" for item in stored if item not in requested]
        return lines or [f"  {name}: same entries, different order or repeats"]
    return [f"  {name}: {_shown(stored)} -> {_shown(requested)}"]


def scope_diff(stored: dict[str, Any], requested: dict[str, Any]) -> list[str]:
    """Field-by-field differences between a stored ``roe.json`` and the requested blocks.

    One line per changed field (``+`` adds a list entry, ``-`` removes one,
    ``old -> new`` otherwise). Empty exactly when every compared block is
    equal: only then may a re-run leave the stored scope as it is.
    """
    lines: list[str] = []
    for block in COMPARED_BLOCKS:
        old, new = stored.get(block, _ABSENT), requested.get(block, _ABSENT)
        if isinstance(old, dict) and isinstance(new, dict):
            for key in [*new, *(k for k in old if k not in new)]:
                lines += _field_diff(f"{block}.{key}", old.get(key, _ABSENT), new.get(key, _ABSENT))
        else:
            lines += _field_diff(block, old, new)
    return lines


def _read_document(path: Path) -> tuple[dict[str, Any], str]:
    """``(document, "")`` for a readable ``roe.json``; ``({}, why not)`` otherwise."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, f"there is no enforced scope at {path}"
    except (OSError, ValueError) as exc:
        return {}, f"the enforced scope {path} cannot be read: {exc}"
    if not isinstance(document, dict):
        return {}, f"the enforced scope {path} is not a JSON object"
    return document, ""


def _confirm_change(slug: str, changes: list[str], assume_yes: bool) -> bool:
    print(f"The stored scope of engagement {slug} differs from this command line:", file=sys.stderr)
    for line in changes:
        print(line, file=sys.stderr)
    if assume_yes:
        print("  replacing the stored scope (--yes)", file=sys.stderr)
        return True
    if not sys.stdin.isatty():
        print(
            "error: the stored scope is kept. Re-run with --yes to replace it (you confirm that "
            f"you are authorized to test the new scope), or with `--resume {slug}` to continue "
            "with the stored one.",
            file=sys.stderr,
        )
        return False
    answer = input("Replace the stored scope? You must be authorized to test the new one. [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def hunt_settings(args: argparse.Namespace, scope: dict[str, Any]) -> dict[str, Any]:
    """What ``--resume`` needs to run this command line again (the ``hunt`` key of ``roe.json``).

    Patterns from ``--scope-file`` are stored resolved, so a resume does not
    depend on that file still being there. ``--yes`` is never stored: a
    confirmation belongs to one invocation.
    """
    derived = set(scope["hosts"])
    if args.include_subdomains:
        derived |= {f"**.{host}" for host in scope["hosts"]}
    return {
        "targets": list(scope["targets"]),
        "rps": scope["rps"],
        "flags": {name: bool(getattr(args, name)) for name in RESUME_FLAGS},
        "options": {
            "scope": [pattern for pattern in scope["in_scope"] if pattern not in derived],
            "exclude": list(scope["out_of_scope"]),
            "crawl_exclude": list(args.crawl_exclude),
            "instruction": args.instruction,
            "mode": args.mode,
            "recon_timeout": int(args.recon_timeout),
            "timeout": int(args.timeout),
            "fail_on": args.fail_on,
        },
    }


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_int(value: Any) -> bool:
    return type(value) is int


_OPTION_CHECKS: dict[str, Any] = {
    "scope": _is_text_list,
    "exclude": _is_text_list,
    "crawl_exclude": _is_text_list,
    "instruction": lambda value: isinstance(value, str),
    "mode": lambda value: value in MODES,
    "recon_timeout": _is_int,
    "timeout": _is_int,
    "fail_on": lambda value: value is None or value in SEVERITIES,
}


def stored_settings(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Parser values (by option name) from a stored ``hunt`` key, or ``({}, problem)``."""
    block = document.get("hunt")
    if not isinstance(block, dict):
        return {}, (
            "its enforced scope holds no hunt settings (it was written by another command or "
            "an older version); name the targets and pass --engagement-name instead"
        )
    targets, rps = block.get("targets"), block.get("rps")
    flags, options = block.get("flags", {}), block.get("options", {})
    bad: list[str] = []
    if not (_is_text_list(targets) and targets):
        bad.append("targets")
    if not _is_int(rps):
        bad.append("rps")
    if not isinstance(flags, dict) or any(type(value) is not bool for value in flags.values()):
        bad.append("flags")
        flags = {}
    if not isinstance(options, dict):
        bad.append("options")
        options = {}
    values: dict[str, Any] = {"targets": targets, "rps": rps}
    values.update({name: flags[name] for name in RESUME_FLAGS if name in flags})
    for name, accepts in _OPTION_CHECKS.items():
        if name not in options:
            continue
        if not accepts(options[name]):
            bad.append(f"options.{name}")
        values[name] = options[name]
    if bad:
        return {}, f"its stored hunt settings are damaged ({', '.join(bad)})"
    return {
        name: list(value) if isinstance(value, list) else value for name, value in values.items()
    }, ""


def _explicit_options(argv: list[str]) -> set[str]:
    """The option names that ``argv`` itself sets (not the ones left at a default)."""
    parser = _build_parser()
    for action in parser._actions:  # noqa: SLF001 - argparse has no public way to ask this
        action.default = argparse.SUPPRESS  # an option left out then sets nothing at all
    return {name for name, value in vars(parser.parse_args(argv)).items() if value != []}


def _valid_name(name: str) -> bool:
    return (
        bool(name.strip())
        and name == name.strip()
        and not name.startswith(".")
        and not any(char in name for char in "/\\\x00")
    )


def apply_resume(args: argparse.Namespace, argv: list[str], control: Path) -> str:
    """Fill ``args`` from the stored settings of ``args.resume``; return a problem or ``""``.

    Stored values replace parser defaults only: an option given on this
    command line wins, and a scope it changes is then confirmed like any other
    scope change.
    """
    name = str(args.resume)
    if args.engagement_name and args.engagement_name != name:
        return (
            f"--resume {name} and --engagement-name {args.engagement_name} "
            "name different engagements"
        )
    if not _valid_name(name):
        return f"{name!r} is not an engagement name"
    document, problem = _read_document(control / name / "roe.json")
    if problem:
        return f"cannot resume {name}: {problem}"
    values, problem = stored_settings(document)
    if problem:
        return f"cannot resume {name}: {problem}"
    explicit = _explicit_options(argv)
    for option, value in values.items():
        if option not in explicit:
            setattr(args, option, value)
    args.engagement_name = name
    return ""


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
    digest["records"] = records
    return path, digest


def capture_available() -> bool:
    from buggy.pipeline.mcp_client import server_configured  # noqa: PLC0415

    return server_configured("capture")


def queue_leads(engagement: str, records: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Queue scanner hits and ranked recon leads as candidates for the agents.

    Deterministic: the capture server classifies and deduplicates them. Returns
    its answer, or ``{"error": ...}`` when the queue cannot be reached.
    """
    from buggy.pipeline.report import rank_candidates  # noqa: PLC0415

    items = {
        "pipeline": records.get("vulnerability", []),
        "ranked": rank_candidates(records),
    }
    return _capture("candidates_add", engagement, items_json=json.dumps(items), actor="recon")


#: Scanner records are sent to the grader slimmed to what it reads, and capped.
_KNOWN_ISSUE_ATTRS = ("class", "cwe", "tags", "template_id", "matched_at")
MAX_KNOWN_ISSUES = 300
#: Unanswered calls in a row after which the sweep stops: the server is gone.
SWEEP_MAX_FAILURES = 3


def _known_issues(records: dict[str, list[dict[str, Any]]]) -> str:
    slim = []
    for record in records.get("vulnerability", [])[:MAX_KNOWN_ISSUES]:
        raw = record.get("attrs")
        attrs: dict[str, Any] = raw if isinstance(raw, dict) else {}
        slim.append(
            {
                "type": "vulnerability",
                "value": record.get("value"),
                "attrs": {k: attrs[k] for k in _KNOWN_ISSUE_ATTRS if k in attrs},
            }
        )
    return json.dumps(slim)


def run_probe_sweep(
    engagement: str, records: dict[str, list[dict[str, Any]]], *, budget: int | None = None
) -> dict[str, Any]:
    """Run the planned read-only probes, then re-prove and grade what they found. No LLM.

    The plan is fixed rules over the recon records (:mod:`buggy.pipeline.sweep`).
    Every request goes through the capture gateway: scope, rate limit and the
    ledger apply. A positive probe is queued by the server; here it is verified
    (the probe is run again) and graded. Nothing state-changing is planned. One
    planned check, ``graphql_checks``, sends its queries with POST: where the
    engagement requires approval the gateway holds it like any POST, and it is
    counted under ``held_for_approval``.
    """
    from buggy.pipeline import sweep  # noqa: PLC0415

    planned = sweep.plan(records, budget=sweep.DEFAULT_BUDGET if budget is None else budget)
    return _run_steps(engagement, planned, _known_issues(records))


def run_state_sweep(
    engagement: str,
    records: dict[str, list[dict[str, Any]]],
    *,
    budget: int | None = None,
    identity: str = "",
) -> dict[str, Any]:
    """Hand the planned state-changing probe runs to the gateway. No LLM.

    These are the business-logic and request-body checks (a negative quantity,
    a privileged field, injection in a JSON body). Each can change state, so
    where the engagement requires approval the gateway holds the run and files
    one request for it: nothing is sent, and the run is counted under
    ``held_for_approval``. A run the operator has allowed is sent on the next
    ``hunt --resume``; a positive result is re-proven and graded like any other.
    """
    from buggy.pipeline import sweep  # noqa: PLC0415

    planned = sweep.plan_state_changing(
        records,
        budget=sweep.DEFAULT_STATE_BUDGET if budget is None else budget,
        identity=identity,
    )
    return _run_steps(engagement, planned, _known_issues(records))


def _run_steps(engagement: str, planned: dict[str, Any], known: str) -> dict[str, Any]:
    """Send the planned probe runs one bug class after another; re-prove and grade positives.

    Returns the counts, in total and per class (``by_class``).
    """
    from buggy.pipeline import sweep  # noqa: PLC0415

    out = _empty_counts()
    out["planned"] = len(planned["steps"])
    out["left_out"] = planned["left_out"]
    failures = 0
    for step in sweep.by_class(planned["steps"]):
        cls = out["by_class"].setdefault(
            sweep.class_of(step["probe"]) or "other", dict.fromkeys(_CLASS_COUNTS, 0)
        )
        result = _capture(
            "probe_run", engagement, probe=step["probe"], params_json=json.dumps(step["params"])
        )
        if result.get("error") and "status" not in result and "code" not in result:
            failures += 1
            if failures >= SWEEP_MAX_FAILURES:
                out["error"] = str(result["error"])[:300]
                break
            continue
        failures = 0
        out["ran"] += 1
        cls["checks"] += 1
        if result.get("status") == "refused":
            out["refused"] += 1
            if result.get("code") == "APPROVAL_REQUIRED":
                # Held by the gateway: a state-changing run, or a read-only check that is
                # sent with POST (a GraphQL query). It waits for the operator.
                out["held_for_approval"] += 1
                cls["held"] += 1
            continue
        if result.get("vulnerable") is False:
            out["not_vulnerable"] += 1
            continue
        if result.get("vulnerable") is not True:
            out["undecided"] += 1
            continue
        out["vulnerable"] += 1
        cls["positive"] += 1
        finding_id = str(result.get("finding_id") or "")
        if not finding_id:
            continue
        entry = {
            "id": finding_id,
            "probe": step["probe"],
            "url": step["params"]["url"],
            "status": "candidate",
            "grade": "",
        }
        entry["status"], entry["grade"] = _prove(engagement, finding_id, known)
        proven = entry["status"] == "exploit_verified"
        out["verified"] += proven
        cls["proven"] += proven
        out["submit"] += entry["grade"] == "submit"
        out["findings"].append(entry)
    return out


def _prove(engagement: str, finding_id: str, known: str) -> tuple[str, str]:
    """Re-prove a queued finding and, if it holds, grade it. Returns ``(status, grade)``."""
    verified = _capture("finding_verify", engagement, finding_id=finding_id)
    raw_finding = verified.get("finding")
    finding: dict[str, Any] = raw_finding if isinstance(raw_finding, dict) else {}
    status = str(finding.get("status") or "candidate")
    if status != "exploit_verified":
        return status, ""
    graded = _capture("finding_grade", engagement, finding_id=finding_id, known_issues_json=known)
    raw_grade = graded.get("grade")
    grade: dict[str, Any] = raw_grade if isinstance(raw_grade, dict) else {}
    return status, str(grade.get("decision") or "")


#: Signed-in testing: how many declared accounts are used, and each one's crawl budget.
MAX_ACCOUNTS = 3
MAX_SEEDS = 10
CRAWL_REQUESTS = 120
SOURCE_CRAWL = "surface_crawl"


def _service_urls(records: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Where a crawl starts: the live services recon found."""
    urls: set[str] = set()
    for record in records.get("http_service", []):
        raw = record.get("attrs")
        attrs: dict[str, Any] = raw if isinstance(raw, dict) else {}
        for value in (attrs.get("url"), record.get("value")):
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                urls.add(value)
                break
    return sorted(urls)[:MAX_SEEDS]


def crawl_records(crawl: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """What a crawl discovered, as the ``url`` records the parameter extractor reads.

    Returns the records and how many forms were left out as destructive.

    A link the crawler itself must never request (it could sign out or change
    something) is not handed on either: a probe would request it. A form sent
    with GET becomes the URL it would request, so its fields are query
    parameters for the read-only sweep, unless the form looks like an action
    (a change-password form is often a GET): then, like a form that posts, it
    stays a form, and its checks wait for approval. A form whose submission
    would destroy data or reconfigure the application is dropped.
    """
    from urllib.parse import urlencode  # noqa: PLC0415

    from buggy.capture.crawl import (  # noqa: PLC0415
        form_changes_state,
        form_destructive_reason,
        never_request_reason,
    )

    out: list[dict[str, Any]] = [
        {"type": "url", "value": url, "source_tool": SOURCE_CRAWL}
        for url in crawl.get("urls") or []
        if isinstance(url, str) and not never_request_reason(url)
    ]
    dropped = 0
    for form in crawl.get("forms") or []:
        if not isinstance(form, dict) or not isinstance(form.get("action"), str):
            continue
        if form_destructive_reason(form) or never_request_reason(form["action"]):
            dropped += 1
            continue
        fields = [f for f in form.get("fields") or [] if isinstance(f, dict) and f.get("name")]
        method = str(form.get("method") or "GET").upper()
        if method == "GET" and not form_changes_state(form):
            action = form["action"].partition("?")[0].partition("#")[0]
            pairs = [(str(f["name"]), str(f.get("value") or "")) for f in fields]
            value = f"{action}?{urlencode(pairs)}" if pairs else action
            out.append({"type": "url", "value": value, "source_tool": SOURCE_CRAWL})
        else:
            out.append(
                {
                    "type": "url",
                    "value": str(form.get("page") or form["action"]),
                    "source_tool": SOURCE_CRAWL,
                    "attrs": {
                        "form": [{"action": form["action"], "method": method, "parameters": fields}]
                    },
                }
            )
    return out, dropped


def _new_parameters(found: list[dict[str, Any]], known: set[str]) -> list[dict[str, Any]]:
    """Parameter records of a crawl that neither recon nor an earlier account produced."""
    from buggy.pipeline.tools import params  # noqa: PLC0415

    fresh: list[dict[str, Any]] = []
    for record in params.extract(found):
        if record.value in known:
            continue
        known.add(record.value)
        fresh.append({"type": "parameter", "value": record.value, "attrs": dict(record.attrs)})
    return fresh


def _add_counts(total: dict[str, Any], part: dict[str, Any]) -> None:
    for name, value in part.items():
        if isinstance(value, bool) or name == "error":
            continue
        if isinstance(value, int):
            total[name] = int(total.get(name) or 0) + value
        elif isinstance(value, list):
            total.setdefault(name, []).extend(value)
        elif name == "by_class" and isinstance(value, dict):
            merged = total.setdefault("by_class", {})
            for cls, counts in value.items():
                into = merged.setdefault(cls, dict.fromkeys(_CLASS_COUNTS, 0))
                for key in _CLASS_COUNTS:
                    into[key] += int(counts.get(key) or 0)
    total["error"] = total.get("error") or part.get("error")


#: What is counted per bug class.
_CLASS_COUNTS = ("checks", "held", "positive", "proven")


def _empty_counts() -> dict[str, Any]:
    return {
        "planned": 0, "left_out": 0, "ran": 0, "vulnerable": 0, "not_vulnerable": 0,
        "undecided": 0, "refused": 0, "held_for_approval": 0, "verified": 0, "submit": 0,
        "findings": [], "error": None, "by_class": {},
    }  # fmt: skip


def run_signed_in(
    engagement: str,
    records: dict[str, list[dict[str, Any]]],
    *,
    budget: int | None = None,
    state_budget: int | None = None,
) -> dict[str, Any]:
    """Test what is behind the login, as the operator's declared test accounts. No LLM.

    For each account (three at most) the gateway signs in and the crawler
    walks the application with GET requests, never following a link that
    could sign out or change something. The inputs found there that recon did
    not know are probed as that account (read-only probes), and the write
    operations found there are handed to the gateway as state-changing runs,
    which wait for approval. What each account could reach is then compared:
    an object only one account reached is asked for as the others, and counts
    as broken access only when the owner's own marker comes back to a
    non-owner. Without declared accounts nothing is sent.
    """
    from buggy.pipeline import sweep  # noqa: PLC0415

    out: dict[str, Any] = {
        "ran": False,
        "reason": None,
        "accounts": [],
        "urls_reached": 0,
        "new_inputs": 0,
        "probes": _empty_counts(),
        "state": _empty_counts(),
        "inferred": {"objects": 0, "broken_access": 0, "enforced": 0, "inconclusive": 0,
                     "verified": 0, "submit": 0, "findings": [], "without_markers": []},
    }  # fmt: skip
    listed = _capture("identities_list", engagement)
    identities = [row for row in listed.get("identities") or [] if isinstance(row, dict)]
    names = [str(row.get("name")) for row in identities if row.get("name")][:MAX_ACCOUNTS]
    if not names:
        out["reason"] = str(
            listed.get("detail") or listed.get("error") or NO_ACCOUNTS.format(engagement=engagement)
        )
        return out
    seeds = _service_urls(records)
    if not seeds:
        out["reason"] = "recon found no live service to start from"
        return out

    known = {str(r.get("value")) for r in records.get("parameter", []) if r.get("value")}
    known_issues = _known_issues(records)
    reached: dict[str, list[str]] = {}
    probe_budget = sweep.DEFAULT_BUDGET if budget is None else max(0, budget)
    write_budget = sweep.DEFAULT_STATE_BUDGET if state_budget is None else max(0, state_budget)
    for name in names:
        crawl = _capture(
            "surface_crawl",
            engagement,
            seeds_json=json.dumps(seeds),
            identity=name,
            max_requests=CRAWL_REQUESTS,
        )
        urls = crawl.get("urls")
        if not isinstance(urls, list):
            out["accounts"].append(
                {
                    "name": name,
                    "error": str(crawl.get("detail") or crawl.get("error") or crawl)[:200],
                }
            )
            continue
        out["ran"] = True
        reached[name] = [u for u in urls if isinstance(u, str)]
        found, dropped = crawl_records(crawl)
        fresh = _new_parameters(found, known)
        out["accounts"].append(
            {
                "name": name,
                "requested": int(crawl.get("requested") or 0),
                "urls": len(reached[name]),
                "forms": len(crawl.get("forms") or []),
                "new_inputs": len(fresh),
                "forms_never_planned": dropped,
                "truncated": bool(crawl.get("truncated")),
            }
        )
        out["urls_reached"] += len(reached[name])
        out["new_inputs"] += len(fresh)

        planned = sweep.plan({"parameter": fresh}, budget=probe_budget)
        for step in planned["steps"]:
            step["params"]["identity"] = name
        done = _run_steps(engagement, planned, known_issues)
        probe_budget = max(0, probe_budget - done["planned"])
        _add_counts(out["probes"], done)

        writes = sweep.plan_state_changing({"parameter": fresh}, budget=write_budget, identity=name)
        done = _run_steps(engagement, writes, known_issues)
        write_budget = max(0, write_budget - done["planned"])
        _add_counts(out["state"], done)

    if len(reached) >= 2:
        _inferred_access(engagement, reached, known_issues, out["inferred"])
    if not out["ran"]:
        out["reason"] = "no declared account could be used (see the accounts list)"
    return out


def _inferred_access(
    engagement: str, reached: dict[str, list[str]], known: str, out: dict[str, Any]
) -> None:
    """Compare what the accounts reached: objects only one of them saw, asked for as the others."""
    inferred = _capture("owners_infer", engagement, reached_json=json.dumps(reached))
    owners = inferred.get("owners")
    out["without_markers"] = [str(n) for n in inferred.get("identities_without_markers") or []]
    if not isinstance(owners, dict) or not owners:
        return
    # An inferred object is only ever reported when its owner's marker leaks, so
    # objects of an account without markers would spend requests for nothing.
    unmarked = set(out["without_markers"])
    urls = sorted(str(url) for url, owner in owners.items() if str(owner) not in unmarked)
    urls = urls[:MAX_ACCESS_URLS]
    if not urls:
        return
    owners = {url: str(owners[url]) for url in urls}
    result = _capture(
        "authz_matrix_run",
        engagement,
        urls_json=json.dumps(urls),
        owners_json=json.dumps(owners),
        inferred_json=json.dumps(urls),
        max_requests=ACCESS_MAX_REQUESTS,
    )
    verdicts = result.get("verdicts")
    if not isinstance(verdicts, dict):
        return
    out["objects"] = len(urls)
    for verdict in verdicts.values():
        name = str(verdict.get("verdict") if isinstance(verdict, dict) else "")
        if name in ("broken_access", "enforced", "inconclusive"):
            out[name] += 1
    queue = result.get("queue")
    ids = queue.get("ids") if isinstance(queue, dict) else None
    for finding_id in [str(i) for i in ids or [] if i]:
        status, grade = _prove(engagement, finding_id, known)
        out["verified"] += status == "exploit_verified"
        out["submit"] += grade == "submit"
        out["findings"].append({"id": finding_id, "status": status, "grade": grade})


#: Most object URLs the access-control sweep asks for, and its request budget.
MAX_ACCESS_URLS = 40
ACCESS_MAX_REQUESTS = 300
NO_ACCOUNTS = (
    "no test accounts are declared; add two in "
    "~/.buggy/secrets/{engagement}/identities.json (docs/findings.md)"
)
NO_OWNED_OBJECTS = (
    "no declared test account lists an object it owns; add owner_of URLs to "
    "~/.buggy/secrets/{engagement}/identities.json (docs/findings.md)"
)


def _owned_urls(identities: list[Any]) -> list[str]:
    """Concrete object URLs the declared accounts own (``owner_of`` without a ``*`` prefix)."""
    urls: set[str] = set()
    for identity in identities:
        owned = identity.get("owner_of") if isinstance(identity, dict) else None
        for url in owned if isinstance(owned, list) else []:
            if isinstance(url, str) and url.startswith(("http://", "https://")) and "*" not in url:
                urls.add(url)
    return sorted(urls)


def run_access_sweep(engagement: str, records: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Ask for every object a test account owns as every other account and as nobody. No LLM.

    This is the access-control check (IDOR, broken object-level authorisation)
    done by code: the operator declares test accounts and what each owns, the
    gateway logs them in and holds their sessions, and the matrix compares who
    received whose data. Only GET requests are sent. A mismatch is queued,
    re-proven and graded like any other finding. Without declared accounts or
    owned objects nothing is sent and ``reason`` says what is missing.
    """
    out: dict[str, Any] = {
        "ran": False,
        "reason": None,
        "accounts": 0,
        "objects": 0,
        "left_out": 0,
        "broken_access": 0,
        "enforced": 0,
        "public": 0,
        "inconclusive": 0,
        "skipped": 0,
        "verified": 0,
        "submit": 0,
        "findings": [],
    }
    listed = _capture("identities_list", engagement)
    if listed.get("error") or listed.get("ok") is False:
        out["reason"] = str(listed.get("detail") or listed.get("error") or "identities unreadable")
        return out
    identities = [row for row in listed.get("identities") or [] if isinstance(row, dict)]
    out["accounts"] = len(identities)
    if not identities:
        out["reason"] = NO_ACCOUNTS.format(engagement=engagement)
        return out
    urls = _owned_urls(identities)
    if not urls:
        out["reason"] = NO_OWNED_OBJECTS.format(engagement=engagement)
        return out
    out["left_out"] = max(0, len(urls) - MAX_ACCESS_URLS)
    urls = urls[:MAX_ACCESS_URLS]
    result = _capture(
        "authz_matrix_run",
        engagement,
        urls_json=json.dumps(urls),
        max_requests=ACCESS_MAX_REQUESTS,
    )
    raw_verdicts = result.get("verdicts")
    if not isinstance(raw_verdicts, dict):
        out["reason"] = str(result.get("detail") or result.get("error") or "the matrix did not run")
        return out
    out["ran"] = True
    out["objects"] = len(urls)
    for verdict in raw_verdicts.values():
        name = str(verdict.get("verdict") if isinstance(verdict, dict) else "")
        if name in ("broken_access", "enforced", "public", "inconclusive"):
            out[name] += 1
    out["skipped"] = len(result.get("skipped") or [])
    queue = result.get("queue")
    ids = queue.get("ids") if isinstance(queue, dict) else None
    known = _known_issues(records)
    for finding_id in [str(i) for i in ids or [] if i]:
        status, grade = _prove(engagement, finding_id, known)
        out["verified"] += status == "exploit_verified"
        out["submit"] += grade == "submit"
        out["findings"].append({"id": finding_id, "status": status, "grade": grade})
    return out


FINDINGS_REPORTS = (("markdown", "report.md"), ("html", "report.html"), ("json", "report.json"))
SARIF_FILE = "findings.sarif"


def write_findings_reports(
    control: Path, engagement: str, summary: dict[str, Any] | None, *, complete: bool
) -> dict[str, Any]:
    """Write the findings report (Markdown, HTML, JSON) and SARIF into the control dir.

    The capture server builds them from the findings store: only findings the
    verifier proved are listed as findings. Returns ``{"written": [...]}`` and,
    when something could not be produced, ``"errors"``.
    """
    directory = control / engagement
    written: list[str] = []
    errors: list[str] = []
    report_json = ""
    slim = {k: v for k, v in (summary or {}).items() if k in ("records", "last_run", "current_run")}
    for fmt, filename in FINDINGS_REPORTS:
        built = _capture(
            "report_build",
            engagement,
            fmt=fmt,
            recon_summary_json=json.dumps(slim) if slim else "",
            complete=complete,
        )
        text = built.get("report") if isinstance(built, dict) else None
        if not isinstance(text, str):
            errors.append(f"{filename}: {(built or {}).get('error') or built}")
            continue
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / filename).write_text(text, encoding="utf-8")
        except OSError as exc:
            errors.append(f"{filename}: {exc}")
            continue
        written.append(filename)
        if fmt == "json":
            report_json = text
    if report_json:
        try:
            from buggy import __version__  # noqa: PLC0415
            from buggy.findings.sarif import to_sarif  # noqa: PLC0415

            document = to_sarif(json.loads(report_json), tool_version=str(__version__))
            (directory / SARIF_FILE).write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            written.append(SARIF_FILE)
        except (ImportError, OSError, ValueError) as exc:
            errors.append(f"{SARIF_FILE}: {exc}")
    return {"written": written, "errors": errors} if errors else {"written": written}


def _notify(event_builder: str, *args: Any) -> None:
    """Tell the operator (if a webhook is configured). Never raises, never blocks long."""
    try:
        from buggy import notify  # noqa: PLC0415

        notifier = notify.Notifier.from_env()
        notifier.notify(getattr(notify, event_builder)(*args))
    except Exception:  # noqa: BLE001, S110 - a notification must never fail a hunt
        pass


def project_graph(engagement: str) -> str:
    """Project the recon store into the knowledge graph when this process can.

    Returns a one-line outcome. The projection needs the graph database and the
    recon store, which only the full stack's operator has; elsewhere it is skipped.
    """
    try:
        from buggy.pipeline import graph_export  # noqa: PLC0415

        if not graph_export._kg_configured():  # noqa: SLF001
            return "skipped (no graph database configured here)"
        code = graph_export.main([engagement])
    except Exception as exc:  # noqa: BLE001 - the graph is a convenience, never a blocker
        return f"skipped ({type(exc).__name__}: {str(exc)[:120]})"
    return "done" if code == 0 else f"failed (exit {code})"


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


def kickoff_text(
    slug: str,
    scope: dict[str, Any],
    *,
    recon_done: bool,
    instruction: str,
    probes: dict[str, Any] | None = None,
) -> str:
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
        "Work the queue: candidates_next returns the leads to prove, most promising first "
        "(scanner hits, recon leads, probe results), already deduplicated and claimed for you. "
        "Read facts_list before starting and record what you learn with fact_add so other "
        "agents do not repeat it; memory_search returns lessons from earlier engagements on "
        "the same technology. recon_coverage shows what recon did not check.",
        "Spend your effort on what needs judgement: choose what to test, run the deterministic "
        "probes (probe_list, probe_run) on the best candidates, and chain confirmed results into "
        "impact. Priorities: access control and IDOR, authentication and session, SSRF, business "
        "logic, API flaws, GraphQL. For access control use identities_list and authz_matrix_run, "
        "or http_send with identity=...; you never handle a credential.",
        (
            "The sandbox has no network path to the target. Send every request with http_send, "
            "probe_run or the browser_* tools; a state-changing request returns APPROVAL_REQUIRED "
            "until the operator allows it, so batch those and keep working on read-only checks."
            if blocked
            else "Prefer http_send, probe_run and browser_* for anything that counts as evidence."
        ),
        "A claim is not a finding. Submit it with finding_submit (cite capture_ids as "
        "assertions against the endpoint you name, and say what the owner should change), then "
        "call finding_verify: only the independent verifier makes it exploit_verified. Fix or "
        "drop what comes back inconclusive, then finding_grade. Also record verified findings "
        "with report_record_finding. No denial of service, no social engineering, no data "
        "beyond what proves the issue.",
    ]
    if probes and probes.get("ran"):
        parts.append(
            f"A read-only probe sweep already ran ({probes['ran']} runs: sqli, xss_reflected, "
            "ssti, open_redirect and path_traversal on GET query parameters, cors on each "
            f"service, graphql_checks; {probes.get('verified', 0)} findings re-proven, see "
            "findings_list). Do not repeat those runs. Use probes where the sweep cannot go: "
            "request bodies, authenticated endpoints, test accounts, and state-changing probes."
        )
    if instruction.strip():
        parts.append(f"Operator instruction: {instruction.strip()}")
    return " ".join(parts)


# ── result ───────────────────────────────────────────────────────────


def _capture(tool: str, engagement: str, **arguments: Any) -> dict[str, Any]:
    from buggy.pipeline.mcp_client import call_mcp_sync  # noqa: PLC0415

    return call_mcp_sync("capture", tool, {"engagement": engagement, **arguments})


def status_sections(slug: str, control: Path) -> dict[str, Any]:
    """The ``buggy-cli status`` snapshot of this engagement; ``{}`` when it cannot be taken.

    Findings and approvals are counted from it, so the result file and
    ``status`` cannot disagree. Of its remote reads only ``findings_list`` is
    made: the recon state is the one this run watched, and captures are not
    part of the result.
    """
    try:
        from buggy.cli import status  # noqa: PLC0415 - only at the end of a run
    except ImportError:
        return {}

    def fetch(server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if (server, tool) == ("capture", "findings_list"):
            return _capture(tool, **arguments)
        return {"error": "not read by hunt"}

    try:
        return status.snapshot(
            slug, control=control, audit=_paths.audit_root(), fetch=fetch, now=time.time()
        )
    except Exception:  # noqa: BLE001 - counts that cannot be read are reported as unavailable
        return {}


def count_findings(section: Any) -> dict[str, Any]:
    """Finding counts from the ``findings`` section of a status snapshot.

    An unavailable section counts as zero and says ``"available": false``. An
    exploit-verified finding whose severity is not one of the five is counted
    under ``unknown`` rather than dropped.
    """
    section = section if isinstance(section, dict) else {}
    counts: dict[str, Any] = {
        "available": bool(section.get("available")),
        "exploit_verified": dict.fromkeys(SEVERITIES, 0),
        "inconclusive": 0,
        "candidates": 0,
    }
    if not counts["available"]:
        return counts
    verified = counts["exploit_verified"]
    for item in section.get("exploit_verified") or []:
        severity = str(item.get("severity") or "").lower() if isinstance(item, dict) else ""
        key = severity if severity in SEVERITIES else "unknown"
        verified[key] = verified.get(key, 0) + 1
    by_status = section.get("by_status")
    by_status = by_status if isinstance(by_status, dict) else {}
    counts["inconclusive"] = int(by_status.get("inconclusive") or 0)
    counts["candidates"] = int(by_status.get("candidate") or 0)
    return counts


def recon_is_complete(state: str) -> bool:
    """False for a recon run that timed out or ended in any state but ``completed``.

    A run this command did not watch (no recon server, ``--no-recon-wait``,
    a mode the pipeline does not run in) is not called incomplete; its state
    in the result file says that it was not watched.
    """
    return state == RECON_COMPLETED or state in RECON_NOT_WATCHED


def recon_outcome(state: str, summary: dict[str, Any] | None) -> dict[str, Any]:
    """The ``recon`` block of the result: how the watch ended and what the store holds."""
    summary = summary or {}
    records = summary.get("records")
    last = summary.get("last_run")
    drops = last.get("scope_drops") if isinstance(last, dict) else None
    return {
        "state": state,
        "records": {
            str(name): count
            for name, count in sorted((records if isinstance(records, dict) else {}).items())
            if type(count) is int
        },
        # The drop count belongs to a finished run; a run still going has none yet.
        "scope_drops": drops if type(drops) is int and state != RECON_TIMED_OUT else None,
    }


_PROBE_COUNTS = (
    "planned", "left_out", "ran", "vulnerable", "not_vulnerable", "undecided", "refused",
    "held_for_approval", "verified", "submit",
)  # fmt: skip


def _probes_result(probes: Any) -> dict[str, Any]:
    """The sweep's counts for the result file; ``{"ran_sweep": False}`` when it did not run."""
    if not isinstance(probes, dict):
        return {"ran_sweep": False}
    counts = {name: int(probes.get(name) or 0) for name in _PROBE_COUNTS}
    return {"ran_sweep": True, **counts, "error": probes.get("error")}


_ACCESS_COUNTS = (
    "accounts", "objects", "left_out", "broken_access", "enforced", "public", "inconclusive",
    "skipped", "verified", "submit",
)  # fmt: skip


def _signed_in_result(signed_in: Any) -> dict[str, Any]:
    """The signed-in stage for the result file: counts only, no finding lists."""
    if not isinstance(signed_in, dict):
        return {"ran": False, "reason": "not run"}
    raw_inferred = signed_in.get("inferred")
    inferred: dict[str, Any] = raw_inferred if isinstance(raw_inferred, dict) else {}
    return {
        "ran": bool(signed_in.get("ran")),
        "reason": signed_in.get("reason"),
        "accounts": [a for a in signed_in.get("accounts") or [] if isinstance(a, dict)],
        "urls_reached": int(signed_in.get("urls_reached") or 0),
        "new_inputs": int(signed_in.get("new_inputs") or 0),
        "probes": _probes_result(signed_in.get("probes")),
        "state": _probes_result(signed_in.get("state")),
        "inferred": {k: v for k, v in inferred.items() if k != "findings"},
    }


def _access_result(access: Any) -> dict[str, Any]:
    """The access-control sweep's counts for the result file."""
    if not isinstance(access, dict):
        return {"ran": False, "reason": "not run"}
    counts = {name: int(access.get(name) or 0) for name in _ACCESS_COUNTS}
    return {"ran": bool(access.get("ran")), "reason": access.get("reason"), **counts}


def build_result(
    slug: str, outcome: dict[str, Any], sections: dict[str, Any], *, now: float
) -> dict[str, Any]:
    """What ``hunt-result.json`` says. ``complete`` is false when recon timed out or
    finished in any state but ``completed``, or when the agent run failed."""
    recon, agent = outcome["recon"], outcome["agent"]
    approvals = sections.get("approvals")
    approvals = approvals if isinstance(approvals, dict) else {}
    return {
        "engagement": slug,
        "finished_at": now,
        "recon": recon,
        "issues": {severity: int(outcome["issues"].get(severity, 0)) for severity in SEVERITIES},
        "findings": count_findings(sections.get("findings")),
        "approvals_pending": int(approvals.get("pending") or 0)
        if approvals.get("available")
        else 0,
        "agent": {
            "ran": bool(agent["ran"]),
            "error": agent["error"],
            **({"runner": str(agent["runner"])} if agent.get("runner") else {}),
        },
        "probes": _probes_result(outcome.get("probes")),
        "access": _access_result(outcome.get("access")),
        "signed_in": _signed_in_result(outcome.get("signed_in")),
        "state": _probes_result(outcome.get("state")),
        "not_tested": list(outcome.get("not_tested") or []),
        "coverage": list(outcome.get("coverage") or []),
        "complete": recon_is_complete(recon["state"]) and not agent["error"],
    }


def gate_count(result: dict[str, Any], fail_on: str | None, include_issues: bool) -> int:
    """How many things are at or above ``fail_on``; 0 without a threshold.

    Exploit-verified findings always count, known issues only with
    ``include_issues``. A verified finding of unknown severity meets every
    threshold: a gate does not pass on a finding it cannot rank.
    """
    if not fail_on:
        return 0
    at_or_above = SEVERITIES[: SEVERITIES.index(fail_on) + 1]
    verified = result["findings"]["exploit_verified"]
    count = sum(verified.get(severity, 0) for severity in at_or_above) + verified.get("unknown", 0)
    if include_issues:
        count += sum(result["issues"].get(severity, 0) for severity in at_or_above)
    return count


def exit_code(result: dict[str, Any], *, fail_on: str | None, fail_on_issues: bool) -> int:
    if not result["complete"]:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if gate_count(result, fail_on, fail_on_issues) else EXIT_OK


def write_result(control: Path, slug: str, result: dict[str, Any]) -> Path:
    """Write ``hunt-result.json`` atomically; a reader never sees half a file."""
    directory = control / slug
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / RESULT_FILE
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".hunt-result-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(result, indent=2) + "\n")
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


# ── entry ────────────────────────────────────────────────────────────


def _sweep_stage(
    args: argparse.Namespace, slug: str, records: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    """Run the probe sweep unless it was turned off; print one summary. ``None`` when skipped."""
    budget = getattr(args, "probe_budget", None)
    if getattr(args, "no_probes", False) or (budget is not None and budget <= 0):
        print("  probe sweep      skipped (--no-probes)", file=sys.stderr)
        return None
    probes = run_probe_sweep(slug, records, budget=budget)
    line = (
        f"{probes['ran']} of {probes['planned']} run, {probes['vulnerable']} positive, "
        f"{probes['verified']} re-proven, {probes['submit']} graded submit"
    )
    if probes["held_for_approval"]:
        line += (
            f", {probes['held_for_approval']} waiting for your approval "
            f"(buggy-cli approvals list {slug})"
        )
    if probes["left_out"]:
        line += f" ({probes['left_out']} more left out by the budget; --probe-budget)"
    if probes["error"]:
        line += f"; stopped: {probes['error']}"
    print(f"  probe sweep      {line}", file=sys.stderr)
    for found in probes["findings"]:
        print(
            f"    {found['id']}  {found['probe']}  {found['status']}"
            + (f"/{found['grade']}" if found["grade"] else "")
            + f"  {found['url']}",
            file=sys.stderr,
        )
    if args.non_interactive:
        print(json.dumps({"type": "probe_sweep", **probes}))
    return probes


def _access_stage(
    args: argparse.Namespace, slug: str, records: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    """Run the access-control sweep unless probes are off; print one summary."""
    if getattr(args, "no_probes", False):
        return None
    access = run_access_sweep(slug, records)
    if not access["ran"]:
        print(f"  access control   not run: {access['reason']}", file=sys.stderr)
    else:
        line = (
            f"{access['objects']} owned objects asked as {access['accounts']} accounts and "
            f"without credentials: {access['broken_access']} readable by a non-owner, "
            f"{access['enforced']} enforced, {access['inconclusive']} could not tell; "
            f"{access['verified']} re-proven, {access['submit']} graded submit"
        )
        if access["left_out"]:
            line += f" ({access['left_out']} more objects left out)"
        print(f"  access control   {line}", file=sys.stderr)
        for found in access["findings"]:
            print(
                f"    {found['id']}  access_control  {found['status']}"
                + (f"/{found['grade']}" if found["grade"] else ""),
                file=sys.stderr,
            )
    if args.non_interactive:
        print(json.dumps({"type": "access_sweep", **access}))
    return access


def _held(counts: dict[str, Any], slug: str) -> str:
    waiting = int(counts.get("held_for_approval") or 0)
    return (
        f", {waiting} waiting for your approval (buggy-cli approvals list {slug})"
        if waiting
        else ""
    )


def _signed_in_stage(
    args: argparse.Namespace, slug: str, records: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    """Test behind the login as the declared accounts; print what happened."""
    if getattr(args, "no_probes", False):
        return None
    result = run_signed_in(
        slug,
        records,
        budget=getattr(args, "probe_budget", None),
        state_budget=getattr(args, "state_probe_budget", None),
    )
    if not result["ran"]:
        print(f"  signed-in        not run: {result['reason']}", file=sys.stderr)
    else:
        used = [a for a in result["accounts"] if "error" not in a]
        probes, state, inferred = result["probes"], result["state"], result["inferred"]
        print(
            f"  signed-in        {len(used)} accounts crawled: {result['urls_reached']} URLs "
            f"reached, {result['new_inputs']} inputs recon had not seen",
            file=sys.stderr,
        )
        for account in result["accounts"]:
            if "error" in account:
                print(f"    {account['name']}: not usable ({account['error']})", file=sys.stderr)
        print(
            f"    read-only probes  {probes['ran']} run, {probes['vulnerable']} positive, "
            f"{probes['verified']} re-proven, {probes['submit']} graded submit"
            + _held(probes, slug),
            file=sys.stderr,
        )
        print(
            f"    write operations  {state['planned']} runs planned, "
            f"{state['ran'] - state['refused']} sent, {state['vulnerable']} positive, "
            f"{state['verified']} re-proven" + _held(state, slug),
            file=sys.stderr,
        )
        if inferred["objects"]:
            print(
                f"    objects one account reached and another did not: {inferred['objects']} "
                f"asked for as the others: {inferred['broken_access']} readable by a "
                f"non-owner, {inferred['enforced']} enforced, {inferred['inconclusive']} could "
                f"not tell; {inferred['verified']} re-proven",
                file=sys.stderr,
            )
        if inferred["without_markers"]:
            print(
                "    no markers declared for: "
                + ", ".join(inferred["without_markers"])
                + " (an inferred object is only reported when the owner's marker leaks; add "
                "`markers` to identities.json)",
                file=sys.stderr,
            )
        for found in [*probes["findings"], *state["findings"], *inferred["findings"]]:
            print(
                f"    {found['id']}  {found.get('probe', 'access_control')}  {found['status']}"
                + (f"/{found['grade']}" if found["grade"] else ""),
                file=sys.stderr,
            )
    if args.non_interactive:
        print(json.dumps({"type": "signed_in", **result}))
    return result


def _state_stage(
    args: argparse.Namespace,
    slug: str,
    records: dict[str, list[dict[str, Any]]],
    signed_in: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Hand the write operations recon knows to the gateway as state-changing runs."""
    budget = getattr(args, "state_probe_budget", None)
    if getattr(args, "no_probes", False) or (budget is not None and budget <= 0):
        return None
    usable = [a["name"] for a in (signed_in or {}).get("accounts") or [] if "error" not in a]
    state = run_state_sweep(slug, records, budget=budget, identity=usable[0] if usable else "")
    if state["planned"]:
        print(
            f"  write operations {state['planned']} state-changing runs planned from the API "
            f"description: {state['ran'] - state['refused']} sent, {state['vulnerable']} "
            f"positive, {state['verified']} re-proven" + _held(state, slug),
            file=sys.stderr,
        )
        for found in state["findings"]:
            print(
                f"    {found['id']}  {found['probe']}  {found['status']}"
                + (f"/{found['grade']}" if found["grade"] else ""),
                file=sys.stderr,
            )
    if args.non_interactive:
        print(json.dumps({"type": "state_sweep", **state}))
    return state


def class_coverage(outcome: dict[str, Any], slug: str) -> list[dict[str, Any]]:
    """One row per bug class: was it tested, how many checks, how many proven, and why not.

    A class counts as tested when at least one of its checks was sent. A check
    that waits for approval was not sent. The reason of an untested class is
    the plain cause: held for approval, no test accounts, no input of that
    kind found, or no automatic check exists for the class.
    """
    from buggy.pipeline import sweep  # noqa: PLC0415

    totals: dict[str, dict[str, int]] = {}
    signed_in = outcome.get("signed_in") if isinstance(outcome.get("signed_in"), dict) else {}
    sections = [outcome.get("probes"), outcome.get("state")]
    sections += [signed_in.get("probes"), signed_in.get("state")]
    for section in sections:
        counted = section.get("by_class") if isinstance(section, dict) else None
        for cls, counts in (counted or {}).items():
            into = totals.setdefault(cls, dict.fromkeys(_CLASS_COUNTS, 0))
            for key in _CLASS_COUNTS:
                into[key] += int(counts.get(key) or 0)

    access = outcome.get("access") if isinstance(outcome.get("access"), dict) else {}
    inferred = signed_in.get("inferred") if isinstance(signed_in.get("inferred"), dict) else {}
    objects = int(access.get("objects") or 0) + int(inferred.get("objects") or 0)
    if objects:
        into = totals.setdefault("access_control", dict.fromkeys(_CLASS_COUNTS, 0))
        into["checks"] += objects
        into["positive"] += int(access.get("broken_access") or 0)
        into["positive"] += int(inferred.get("broken_access") or 0)
        into["proven"] += int(access.get("verified") or 0) + int(inferred.get("verified") or 0)

    accounts = bool(signed_in.get("ran"))
    rows: list[dict[str, Any]] = []
    for cls in sweep.CLASS_ORDER:
        counts = totals.get(cls) or dict.fromkeys(_CLASS_COUNTS, 0)
        sent = counts["checks"] - counts["held"]
        reason = ""
        if sent <= 0:
            if counts["held"]:
                reason = (
                    f"{counts['held']} checks wait for your approval "
                    f"(buggy-cli approvals list {slug})"
                )
            elif cls == "access_control":
                reason = str(
                    access.get("reason")
                    or signed_in.get("reason")
                    or "no object was found that only one test account owns"
                )
            elif cls in sweep.NO_AUTOMATIC_CHECK:
                reason = sweep.NO_AUTOMATIC_CHECK[cls]
            elif outcome.get("probes") is None:
                reason = "the probe stages did not run"
            elif not accounts:
                reason = "recon found no input of this kind; nothing behind the login was reached"
            else:
                reason = "no input of this kind was found, signed in or not"
        rows.append(
            {
                "class": cls,
                "tested": sent > 0,
                "checks": max(sent, 0),
                "waiting_for_approval": counts["held"],
                "findings": counts["proven"],
                "reason": reason,
            }
        )
    return rows


def print_coverage(rows: list[dict[str, Any]]) -> None:
    """The class table, one line per class, in testing order."""
    print("\n  bug classes, in the order they were tested", file=sys.stderr)
    for row in rows:
        if row["tested"]:
            line = f"{row['checks']} checks, {row['findings']} proven"
            if row["waiting_for_approval"]:
                line += f", {row['waiting_for_approval']} waiting for approval"
        else:
            line = f"not tested: {row['reason']}"
        print(f"    {row['class']:<17}{line}", file=sys.stderr)


def not_tested(
    slug: str,
    args: argparse.Namespace,
    probes: dict[str, Any] | None,
    access: dict[str, Any] | None,
    *,
    agents_ran: bool = False,
    signed_in: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """What this run did not test, and what would make it tested. Plain facts for the operator.

    A hunt that only printed scanner results looks finished when it is not;
    this list says which kinds of testing did not happen and the one thing
    that enables each.
    """
    missing: list[dict[str, str]] = []
    if probes is None:
        missing.append(
            {
                "area": "injection, redirect, traversal and CORS probes",
                "reason": "the probe sweep did not run (no evidence gateway here, recon did "
                "not finish, or --no-probes)",
                "enable": "run the full stack without --no-probes",
            }
        )
    if access is None or not access.get("ran"):
        missing.append(
            {
                "area": "access control between users (IDOR)",
                "reason": str(
                    (access or {}).get("reason") or "the access-control sweep did not run"
                ),
                "enable": f"declare two test accounts and what each owns in "
                f"~/.buggy/secrets/{slug}/identities.json",
            }
        )
    if probes is not None and not (signed_in or {}).get("ran"):
        missing.append(
            {
                "area": "everything behind the login",
                "reason": str((signed_in or {}).get("reason") or "no signed-in crawl or probe ran"),
                "enable": f"declare test accounts in ~/.buggy/secrets/{slug}/identities.json",
            }
        )
    agents_off = bool(getattr(args, "no_agent", False)) or (
        not getattr(args, "force_agent", False) and not model_configured()
    )
    if agents_off and not agents_ran:
        missing.append(
            {
                "area": "business logic, authentication flows, request bodies, chained findings",
                "reason": "these need judgement, which is the agents' job, and no agent run "
                "started (--no-agent, or no model is configured)",
                "enable": f"run `buggy agent {slug}` to use Claude Code on this machine (no "
                "model key), or configure a model with `buggy onboard` and run "
                f"`buggy hunt --resume {slug}`",
            }
        )
    missing.append(
        {
            "area": "anything that changes state (orders, payments, account changes)",
            "reason": "state-changing requests and probe runs wait for a person",
            "enable": f"`buggy-cli approvals list {slug}` then `approvals allow`",
        }
    )
    return missing


def run_stages(  # noqa: PLR0912, PLR0915
    args: argparse.Namespace,
    slug: str,
    scope: dict[str, Any],
    control: Path,
    workspace: Path,
    *,
    since: float,
) -> dict[str, Any]:
    """Recon, report and agents. Returns what happened, for the result file."""
    issues = dict.fromkeys(SEVERITIES, 0)
    agent: dict[str, Any] = {"ran": False, "error": None}
    probes: dict[str, Any] | None = None
    access: dict[str, Any] | None = None
    signed_in: dict[str, Any] | None = None
    writes: dict[str, Any] | None = None
    state, summary = "skipped", None
    recon_done = False
    if args.mode != "enforce":
        print("\n[2/4] recon skipped: the pipeline only runs in enforce mode", file=sys.stderr)
    elif not recon_available():
        state = "not_watched"
        print(
            "\n[2/4] recon not watched: this shell cannot reach the recon server "
            "(BUGGY_MCP_RECON_URL). The pipeline service still runs on its own.",
            file=sys.stderr,
        )
    elif args.no_recon_wait:
        state = "background"
        print("\n[2/4] recon started in the background (--no-recon-wait)", file=sys.stderr)
    else:
        print("\n[2/4] recon: deterministic pipeline, no LLM", file=sys.stderr)
        summary = wait_for_recon(
            slug,
            timeout=float(args.recon_timeout),
            since=since,
            quiet=args.non_interactive,
        )
        if summary.get("error"):
            state = "unavailable"
            print(f"  recon unavailable: {summary['error']}", file=sys.stderr)
        else:
            recon_done = not summary.get("timed_out")
            if summary.get("timed_out"):
                state = RECON_TIMED_OUT
                print("  recon is still running; continuing with what exists", file=sys.stderr)
            else:
                state = str((summary.get("last_run") or {}).get("status") or "unknown")
            try:
                path, digest = write_report(control, slug, scope, summary)
            except OSError as exc:
                print(f"  could not write the report: {exc}", file=sys.stderr)
            else:
                issues = {severity: int(digest["issues"].get(severity, 0)) for severity in issues}
                listed = ", ".join(f"{n} {s}" for s, n in digest["issues"].items() if n) or "none"
                print("\n[3/4] recon report (no LLM)", file=sys.stderr)
                print(f"  live services    {digest['services']}", file=sys.stderr)
                print(f"  known issues     {listed}", file=sys.stderr)
                print(f"  exposed secrets  {digest['secrets']}", file=sys.stderr)
                print(f"  test candidates  {digest['candidates']}", file=sys.stderr)
                print(f"  report           {_host_path(path)}", file=sys.stderr)
                records = digest.pop("records", {})
                if capture_available():
                    queued = queue_leads(slug, records)
                    if queued.get("error") or queued.get("ok") is False:
                        print(
                            f"  leads            not queued ({queued.get('error') or queued})",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"  leads queued     {len(queued.get('ids') or [])} "
                            f"({queued.get('created', 0)} new, {queued.get('merged', 0)} merged, "
                            f"{queued.get('unclassified', 0)} scanner hits without a class left out)",
                            file=sys.stderr,
                        )
                    probes = _sweep_stage(args, slug, records)
                    access = _access_stage(args, slug, records)
                    signed_in = _signed_in_stage(args, slug, records)
                    writes = _state_stage(args, slug, records, signed_in)
                print(f"  knowledge graph  {project_graph(slug)}", file=sys.stderr)
                if args.non_interactive:
                    print(json.dumps({"type": "recon_report", "path": str(path), **digest}))
            _notify("recon_event", {**summary, "engagement": slug})
    outcome = {
        "recon": recon_outcome(state, summary),
        "issues": issues,
        "agent": agent,
        "probes": probes,
        "access": access,
        "signed_in": signed_in,
        "state": writes,
    }
    outcome["not_tested"] = not_tested(slug, args, probes, access, signed_in=signed_in)
    outcome["coverage"] = class_coverage(outcome, slug)
    if probes is not None:
        print_coverage(outcome["coverage"])

    if args.no_agent:
        print("\n[4/4] agents skipped (--no-agent)", file=sys.stderr)
        return outcome
    if not args.force_agent and not model_configured():
        print(
            "\n[4/4] agents skipped: no model is configured. Run the agent stage with Claude "
            f"Code on this machine (no key needed): `buggy agent {slug}`. Or run `buggy onboard` "
            f"to add a model, then `buggy hunt --resume {slug}`. "
            "(--force-agent starts the built-in agents anyway.)",
            file=sys.stderr,
        )
        return outcome

    print(
        "\n[4/4] agents: choosing what to test, running probes, chaining findings", file=sys.stderr
    )
    agent["ran"] = True
    try:
        result = _stream_kickoff(
            langgraph_url=args.langgraph_url,
            assistant=args.assistant or os.getenv("BUGGY_LANGGRAPH_ASSISTANT", "buggy"),
            engagement_name=slug,
            kickoff=kickoff_text(
                slug, scope, recon_done=recon_done, instruction=args.instruction, probes=probes
            ),
            timeout_seconds=args.timeout,
            non_interactive=args.non_interactive,
        )
    except Exception as exc:  # noqa: BLE001 - recon and the report already stand on their own
        agent["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        _notify("failure_event", slug, "agents", agent["error"])
        print(
            f"  the agent run did not complete: {agent['error']}\n"
            + (
                "  Recon and the report above are complete. "
                if recon_done
                else "  Recon continues in the pipeline service. "
            )
            + "Check that a model is configured (`buggy onboard`) and that the langgraph "
            f"service is healthy, then re-run with --engagement-name {slug} to continue.",
            file=sys.stderr,
        )
        return outcome

    findings = sorted((workspace / slug).glob("findings/FIND-*.md"))
    print(f"\ndone: {slug} ({result.get('event_count', 0)} agent events)", file=sys.stderr)
    print(
        f"  findings         {len(findings)} under {workspace / slug / 'findings'}", file=sys.stderr
    )
    print(f"  approvals        buggy-cli approvals list {slug}", file=sys.stderr)
    print(f"  audit ledger     buggy-cli audit {slug}", file=sys.stderr)
    return outcome


_RUNNER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$")
_POINTER_NAME = re.compile(r"^\.hunt-[A-Za-z0-9]{6,40}\.json$")
POINTER_ENV = "BUGGY_HUNT_POINTER"


def finalize_outcome(control: Path, slug: str, args: argparse.Namespace) -> dict[str, Any]:
    """The outcome of a run whose agent stage happened outside this command.

    Recon, the probe sweep and the access-control check are taken from the
    result this engagement already has; nothing is run again. The findings
    are read fresh by the caller, so what the outside agent proved is counted.
    """
    try:
        prior = json.loads((control / slug / RESULT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        prior = {}
    prior = prior if isinstance(prior, dict) else {}

    def section(name: str) -> dict[str, Any] | None:
        value = prior.get(name)
        return value if isinstance(value, dict) else None

    recon, access = section("recon"), section("access")
    probes: dict[str, Any] = section("probes") or {}
    issues: dict[str, Any] = section("issues") or {}
    runner = args.agent_runner if _RUNNER_NAME.match(args.agent_runner or "") else "external"
    kept_probes = probes if probes.get("ran_sweep") else None
    return {
        "recon": recon or recon_outcome("skipped", None),
        "issues": {severity: int(issues.get(severity) or 0) for severity in SEVERITIES},
        "agent": {"ran": True, "error": None, "runner": runner},
        "probes": kept_probes,
        "access": access,
        "not_tested": not_tested(slug, args, kept_probes, access, agents_ran=True),
    }


def write_pointer(control: Path, slug: str) -> None:
    """Tell the launcher that started this command which engagement it became.

    The launcher names a one-time file in ``BUGGY_HUNT_POINTER``; the engagement
    name is derived here, so this is how it learns it. Any other name is ignored.
    """
    name = os.environ.get(POINTER_ENV, "")
    if not _POINTER_NAME.match(name):
        return
    try:
        (control / name).write_text(json.dumps({"engagement": slug}) + "\n", encoding="utf-8")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911, PLR0912, PLR0915
    argv = list(sys.argv[1:] if argv is None else argv)
    args = _build_parser().parse_args(argv)
    control = _paths.control_root(args.control_root)
    if args.resume is not None:
        problem = apply_resume(args, argv, control)
        if problem:
            print(f"error: {problem}", file=sys.stderr)
            return EXIT_CONFIG
    if args.fail_on_issues and not args.fail_on:
        print("error: --fail-on-issues needs a threshold: add --fail-on SEVERITY", file=sys.stderr)
        return EXIT_CONFIG
    if args.finalize and args.resume is None:
        print("error: --finalize continues an engagement: add --resume NAME", file=sys.stderr)
        return EXIT_CONFIG
    if not any(target.strip() for target in args.targets):
        print(
            "error: name at least one target, or an engagement to continue with --resume NAME",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    try:
        scope = build_scope(args)
    except RuntimeError as exc:  # unreadable or malformed --scope-file
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    errors = pattern_errors([*scope["in_scope"], *scope["out_of_scope"]])
    errors += _validate_scope_entries(scope["in_scope"], scope["out_of_scope"])
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    slug = _slug(scope["hosts"], args.engagement_name)
    stored_path = control / slug / "roe.json"
    resumed = False
    if args.engagement_name and (stored_path.exists() or stored_path.is_symlink()):
        # An engagement of this name has a scope. Leave it alone when this
        # command line asks for the same one; replace it only after a yes.
        stored, problem = _read_document(stored_path)
        changes = (
            [f"  {problem}; it would be replaced"]
            if problem
            else scope_diff(stored, requested_blocks(scope, args.mode))
        )
        if not changes:
            resumed = True
            print(f"resuming {slug}", file=sys.stderr)
        elif not _confirm_change(slug, changes, args.yes):
            print(
                "not started; the stored scope was not changed and nothing was sent",
                file=sys.stderr,
            )
            return EXIT_CONFIG
    elif not _confirm(scope, args.yes):
        print("not started; nothing was written or sent", file=sys.stderr)
        return EXIT_CONFIG

    started_at = time.time()
    workspace = _paths.workspace_root(args.workspace_root)
    if not resumed:
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
                document_extra={**scope["document_extra"], "hunt": hunt_settings(args, scope)},
                generated_by="buggy-cli hunt",
            )
        except OSError as exc:
            print(
                f"error: cannot write the scope: {exc}\n"
                "The enforced scope lives under the operator-controlled root. Run this on the "
                "host, or with `docker compose --profile operator run --rm operator buggy-cli "
                "hunt ...`.",
                file=sys.stderr,
            )
            return EXIT_CONFIG

    print(
        f"\n[1/4] scope enforced for engagement {slug}"
        + (" (stored scope unchanged, not rewritten)" if resumed else ""),
        file=sys.stderr,
    )
    for line in _describe(scope, args.mode):
        print(line, file=sys.stderr)
    if args.plan_only:
        print(
            "--plan-only: scope already in place, nothing started"
            if resumed
            else "--plan-only: scope written, nothing started",
            file=sys.stderr,
        )
        return EXIT_OK

    # A resumed engagement continues from the pipeline run that exists: the
    # pipeline starts a new one only for a scope it has not run against.
    if args.finalize:
        if not resumed:
            print("error: --finalize needs an engagement that already ran", file=sys.stderr)
            return EXIT_CONFIG
        print(
            "\n[finalize] agent stage done outside this command; nothing is re-run", file=sys.stderr
        )
        outcome = finalize_outcome(control, slug, args)
    else:
        outcome = run_stages(
            args, slug, scope, control, workspace, since=0.0 if resumed else started_at
        )
    result = build_result(slug, outcome, status_sections(slug, control), now=time.time())
    code = exit_code(result, fail_on=args.fail_on, fail_on_issues=args.fail_on_issues)
    try:
        path = write_result(control, slug, result)
    except OSError as exc:
        print(f"error: cannot write {control / slug / RESULT_FILE}: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE
    write_pointer(control, slug)
    print(f"\n  result           {_host_path(path)}", file=sys.stderr)
    if capture_available():
        reports = write_findings_reports(
            control,
            slug,
            {"records": outcome["recon"]["records"]},
            complete=bool(result["complete"]),
        )
        if reports["written"]:
            print(
                f"  findings report  {_host_path(control / slug)}/ "
                f"({', '.join(reports['written'])})",
                file=sys.stderr,
            )
        for problem in reports.get("errors", []):
            print(f"  findings report  not written: {problem}", file=sys.stderr)
    if result.get("not_tested"):
        print("\n  not tested in this run", file=sys.stderr)
        for item in result["not_tested"]:
            print(f"    - {item['area']}", file=sys.stderr)
            print(f"        why: {item['reason']}", file=sys.stderr)
            print(f"        to enable: {item['enable']}", file=sys.stderr)
    if not result["complete"]:
        reasons = []
        if not recon_is_complete(result["recon"]["state"]):
            reasons.append(f"recon {result['recon']['state']}")
        if result["agent"]["error"]:
            reasons.append("the agent run failed")
        print(
            f"  incomplete       {', '.join(reasons)}; continue with "
            f"`buggy-cli hunt --resume {slug}` (exit {code})",
            file=sys.stderr,
        )
    elif code == EXIT_FINDINGS:
        count = gate_count(result, args.fail_on, args.fail_on_issues)
        print(
            f"  gate             {count} at or above {args.fail_on} (exit {code})",
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
