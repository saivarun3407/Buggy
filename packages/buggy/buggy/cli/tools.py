"""``buggy-cli tools`` — which declared tools and specialist domains work in this stack.

    buggy-cli tools check [--json] [--domain NAME] [--require DOMAIN]
    buggy-cli tools script

``check`` probes every registry binary inside the sandbox with a version flag
only (see :mod:`buggy.readiness`), reads which compose services are running,
and prints one line per domain: ``ready``, ``degraded (missing: ...)`` or
``not available in this stack (needs profile X)``. Exit 0 always, unless
``--require DOMAIN`` names a domain that is not ready (exit 4).

Where the probe runs:

* default: the sandbox backend's ``execute`` (``SANDBOX_URL``/``SANDBOX_TOKEN``);
* ``--probe-output FILE``: lines already produced by ``buggy-cli tools script``
  run in the sandbox (``docker compose exec -T sandbox sh < probe.sh``);
* ``--local``: this machine's ``sh`` (useful inside the sandbox image itself).

Running services come from ``--services a,b`` or ``docker compose ps``.
Every side effect is a keyword argument of :func:`main` so tests use fakes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from buggy import readiness

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 4

#: Upper bound for the whole probe script inside the sandbox.
DEFAULT_SCRIPT_TIMEOUT = 900

Execute = Callable[[str], str]
Run = Callable[[Sequence[str]], tuple[int, str]]


def _run_command(argv: Sequence[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, never a shell
            list(argv), capture_output=True, text=True, timeout=30, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return done.returncode, done.stdout if done.returncode == 0 else done.stderr


def _sandbox_execute(timeout: int) -> Execute:
    def execute(script: str) -> str:
        from buggy.backends.factory import build_sandbox_backend

        return build_sandbox_backend().execute(script, timeout=timeout).output

    return execute


def _local_execute(timeout: int) -> Execute:
    def execute(script: str) -> str:
        done = subprocess.run(  # noqa: S603 - the generated probe script on stdin
            ["sh"], input=script, capture_output=True, text=True, timeout=timeout, check=False
        )
        return done.stdout

    return execute


def running_services(run: Run) -> list[str] | None:
    """Services ``docker compose ps`` reports running, or ``None`` if it cannot tell."""
    code, out = run(["docker", "compose", "ps", "--services", "--status", "running"])
    if code != 0:
        return None
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def _default_compose() -> Path | None:
    for base in (Path.cwd(), *Path(__file__).resolve().parents):
        candidate = base / "docker-compose.yml"
        if candidate.is_file():
            return candidate
    return None


def render_table(domains: Sequence[dict], tools: Sequence[readiness.ToolStatus]) -> str:
    width = max((len(d["domain"]) for d in domains), default=0)
    lines = [f"{d['domain']:<{width}}  {d['status']}" for d in domains]
    found = sum(1 for t in tools if t.found)
    missing = sum(1 for t in tools if t.found is False)
    unknown = sum(1 for t in tools if t.found is None)
    lines.append("")
    lines.append(f"binaries: {found} found, {missing} missing, {unknown} not probed")
    notes = sorted({d["note"] for d in domains if d["note"]})
    lines.extend(f"note: {n}" for n in notes)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="buggy-cli tools", description="Tool and domain readiness for this stack."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    chk = sub.add_parser("check", help="probe tools and print the domain matrix")
    chk.add_argument("--json", action="store_true", help="print tools and domains as JSON")
    chk.add_argument("--domain", help="show only this domain")
    chk.add_argument("--require", help="exit 4 unless this domain is ready")
    chk.add_argument("--services", help="comma-separated running services (skip docker)")
    chk.add_argument("--compose", type=Path, help="compose file for profile services")
    where = chk.add_mutually_exclusive_group()
    where.add_argument("--probe-output", type=Path, help="parse saved probe-script output")
    where.add_argument("--local", action="store_true", help="run the probe with local sh")
    chk.add_argument("--timeout", type=int, default=DEFAULT_SCRIPT_TIMEOUT)
    sub.add_parser("script", help="print the probe script (version flags only)")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    execute: Execute | None = None,
    run: Run | None = None,
    specs: Sequence[readiness.ToolSpec] | None = None,
) -> int:
    """Entry point. ``execute``, ``run`` and ``specs`` replace the real world in tests."""
    args = _build_parser().parse_args(argv)
    out = sys.stdout if stdout is None else stdout
    specs = readiness.binaries() if specs is None else list(specs)

    if args.command == "script":
        print(readiness.probe_script(specs), end="", file=out)
        return EXIT_OK

    names = {d.name for d in readiness.DOMAINS}
    for wanted in (args.domain, args.require):
        if wanted and wanted not in names:
            print(f"unknown domain {wanted!r}; known: {', '.join(sorted(names))}", file=sys.stderr)
            return EXIT_USAGE

    if execute is None:
        if args.probe_output:
            text = args.probe_output.read_text(encoding="utf-8", errors="replace")
            execute = lambda _script: text  # noqa: E731
        elif args.local:
            execute = _local_execute(args.timeout)
        else:
            execute = _sandbox_execute(args.timeout)
    tools = readiness.check(execute, specs)

    if args.services is not None:
        services: list[str] | None = [s.strip() for s in args.services.split(",") if s.strip()]
    else:
        services = running_services(run or _run_command)

    compose = args.compose or _default_compose()
    profile_services = readiness.compose_profile_services(compose) if compose else {}

    domains = readiness.domain_readiness(
        tools, services, profile_services=profile_services, specs=specs
    )
    shown = [d for d in domains if not args.domain or d["domain"] == args.domain]

    if args.json:
        payload = {
            "running_services": services,
            "tools": [t.as_dict() for t in tools],
            "domains": shown,
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        print(render_table(shown, tools), file=out)

    if args.require:
        verdict = next(d for d in domains if d["domain"] == args.require)
        if not verdict["ready"]:
            return EXIT_NOT_READY
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
