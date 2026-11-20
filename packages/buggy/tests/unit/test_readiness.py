"""Tool and domain readiness (F4): registry-derived probe, parser, domains, CLI.

The probe script is checked two ways: parsed (every binary invocation is
``<bin> <version flag>`` and nothing else) and run for real with ``sh`` against
binaries that exist or do not exist on this machine.
"""

from __future__ import annotations

import dataclasses
import io
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from buggy import readiness
from buggy.cli import tools as tools_cli
from buggy.graph_registry import STANDARD_GRAPHS
from buggy.readiness import ToolSpec, ToolStatus
from buggy_core.capabilities import (
    CAPABILITY_REGISTRY,
    ROLE_CAPABILITY_POLICY,
    Capability,
    Lifecycle,
)

REPO = Path(__file__).resolve().parents[4]

FAKE_CAP = Capability(
    id="zz-fake-scanner",
    category="recon",
    description="test-only capability",
    binaries=("zz-fake-scanner",),
    delivery="base",
)


def _line(binary: str, found: bool, path: str = "", version: str = "", error: str = "") -> str:
    return json.dumps(
        {"binary": binary, "found": found, "path": path, "version": version, "error": error}
    )


def _all_found(specs) -> str:
    return "\n".join(
        _line(s.binary, True, f"/usr/bin/{s.binary}", f"{s.binary} 1.0") for s in specs if s.probed
    )


# ── tool list derived from the registry ──────────────────────────────


def test_binaries_cover_every_registry_binary_and_nothing_else():
    specs = readiness.binaries()
    expected = {
        b
        for cap in CAPABILITY_REGISTRY
        if cap.lifecycle in readiness.PROBED_LIFECYCLES
        for b in cap.binaries
    }
    assert {s.binary for s in specs} == expected
    nmap = next(s for s in specs if s.binary == "nmap")
    assert nmap.capability == "nmap" and "recon" in nmap.domains


def test_adding_a_capability_shows_up_in_script_and_matrix():
    registry = (*CAPABILITY_REGISTRY, FAKE_CAP)
    specs = readiness.binaries(registry)
    fake = next(s for s in specs if s.binary == "zz-fake-scanner")
    assert "recon" in fake.domains
    assert "'zz-fake-scanner' --version" in readiness.probe_script(specs)

    output = _all_found([s for s in specs if s.binary != "zz-fake-scanner"])
    statuses = readiness.parse_probe_output(output, specs)
    rows = readiness.domain_readiness(statuses, [], specs=specs)
    recon = next(r for r in rows if r["domain"] == "recon")
    assert recon["status"] == "degraded (missing: zz-fake-scanner (no probe result))"

    # Negative control: without the fake capability recon is ready.
    base = readiness.binaries()
    base_rows = readiness.domain_readiness(
        readiness.parse_probe_output(_all_found(base), base), [], specs=base
    )
    assert next(r for r in base_rows if r["domain"] == "recon")["ready"] is True


def test_every_agent_role_has_a_domain():
    names = {d.name for d in readiness.DOMAINS}
    assert set(STANDARD_GRAPHS) <= names
    assert set(ROLE_CAPABILITY_POLICY) <= names
    categories = {c.category for c in CAPABILITY_REGISTRY}
    for domain in readiness.DOMAINS:
        assert set(domain.categories) <= categories, domain.name


# ── probe script ─────────────────────────────────────────────────────


def _invocations(script: str) -> list[list[str]]:
    """Argv after ``timeout -k 1 5`` for every ``timeout`` line, redirects removed."""
    found = []
    for line in script.splitlines():
        match = re.search(r"\$\((timeout .*)\)\s*$", line)
        if not match:
            continue
        argv = [t for t in shlex.split(match.group(1)) if not re.match(r"^\d*[<>]", t)]
        assert argv[:4] == ["timeout", "-k", "1", str(readiness.PROBE_TIMEOUT_SECONDS)], line
        found.append(argv[4:])
    return found


def test_script_runs_each_binary_only_with_a_version_flag():
    specs = readiness.binaries((*CAPABILITY_REGISTRY, FAKE_CAP))
    script = readiness.probe_script(specs)
    invocations = _invocations(script)
    probed = {s.binary for s in specs if s.probed}
    assert {argv[0] for argv in invocations} == probed
    for argv in invocations:
        assert len(argv) == 2 and argv[1] in readiness.VERSION_FLAGS, argv
    # Every line that names a probed binary is a lookup, a timed invocation or an emit.
    for line in script.splitlines():
        for binary in probed:
            if f"'{binary}'" in line:
                assert re.search(r"command -v|\$\(timeout |_emit ", line), line
    # Stdin closed and display unset for every invocation.
    for line in script.splitlines():
        if "$(timeout " in line:
            assert line.rstrip().endswith("<&-)"), line
    assert "unset DISPLAY" in script


def test_parser_on_script_that_would_pass_a_target_fails():
    """Negative control: the parser catches an invocation with an extra argument."""
    script = readiness.probe_script([ToolSpec("nmap", "nmap", "nmap", ())])
    bad = script.replace("'nmap' --version", "'nmap' --version scanme.example")
    with pytest.raises(AssertionError):
        for argv in _invocations(bad):
            assert len(argv) == 2 and argv[1] in readiness.VERSION_FLAGS, argv


def test_unsafe_binary_name_is_refused():
    with pytest.raises(ValueError):
        readiness.probe_script([ToolSpec("x", "nmap; rm -rf /", "x", ())])


def test_sidecar_is_not_probed_but_reported():
    ghidra = next(s for s in readiness.binaries() if s.binary == "ghidra")
    assert ghidra.probed is False
    assert "'ghidra'" not in readiness.probe_script(readiness.binaries())
    status = readiness.parse_probe_output("", [ghidra])[0]
    assert status.found is None and "sidecar" in status.error


# ── probe output parsing ─────────────────────────────────────────────


SPECS = [ToolSpec(b, b, b, ()) for b in ("withver", "nover", "absent", "slow", "silent")]


def test_parse_found_with_version_without_version_missing_and_timeout():
    output = "\n".join(
        [
            "noise from the sandbox",
            _line("withver", True, "/usr/bin/withver", "withver 2.3.1"),
            _line("nover", True, "/usr/bin/nover", "", "no version flag answered (exit 1)"),
            _line("absent", False, "", "", "not found"),
            _line("slow", True, "/usr/bin/slow", "", "timeout after 5s"),
            "{broken json",
            "<stderr>whatever</stderr>",
        ]
    )
    got = {s.binary: s for s in readiness.parse_probe_output(output, SPECS)}
    assert got["withver"] == ToolStatus(
        "withver", "withver", True, "/usr/bin/withver", "withver 2.3.1"
    )
    assert got["nover"].found is True and got["nover"].version == ""
    assert "no version flag" in got["nover"].error
    assert got["absent"].found is False and got["absent"].error == "not found"
    assert got["slow"].found is True and got["slow"].error == "timeout after 5s"
    assert got["silent"].found is None and got["silent"].error == "no probe output"


def _make_bin(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("timeout") is None, reason="needs coreutils timeout")
def test_generated_script_runs_for_real_with_sh(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "ran-with-other-args"
    # Answers only -V; any other argument list is recorded as a violation.
    _make_bin(
        bindir,
        "zz-vonly",
        f'if [ "$1" = -V ] && [ $# = 1 ]; then echo "zz-vonly v9"; exit 0; fi\n'
        f'[ "$1" = --version ] && [ $# = 1 ] && exit 2\necho "$@" >> {marker}; exit 2',
    )
    # A REPL: reads stdin until EOF. With stdin closed it must not hang.
    _make_bin(bindir, "zz-repl", "cat; exit 3")
    # Hangs on any version flag: must be stopped by timeout.
    _make_bin(bindir, "zz-hang", "sleep 30")
    monkeypatch.setenv(
        "PATH", f"{bindir}:{Path(shutil.which('sh')).parent}:/usr/local/bin:/usr/bin:/bin"
    )
    names = ["sh", "python3", "zz-no-such-binary-anywhere", "zz-vonly", "zz-repl", "zz-hang"]
    specs = [ToolSpec(n, n, n, ()) for n in names if n != "python3" or shutil.which(n)]
    script_path = tmp_path / "probe.sh"
    script_path.write_text(readiness.probe_script(specs))
    # stdin is a pipe held open for the whole run: a REPL that read the
    # inherited stdin would block until timeout instead of seeing it closed.
    with subprocess.Popen(
        ["sh", str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()
        returncode = proc.wait(timeout=60)
        proc.stdin.close()
    assert returncode == 0, stderr
    done = subprocess.CompletedProcess([], returncode, stdout, stderr)
    raw = [json.loads(line) for line in done.stdout.splitlines()]
    assert [r["binary"] for r in raw] == [s.binary for s in specs]
    got = {s.binary: s for s in readiness.parse_probe_output(done.stdout, specs)}

    assert got["sh"].found is True and got["sh"].path.endswith("/sh")
    if "python3" in got:
        assert got["python3"].found is True
        assert got["python3"].version.startswith("Python 3.")
    assert got["zz-no-such-binary-anywhere"].found is False
    assert got["zz-vonly"].version == "zz-vonly v9"
    assert got["zz-repl"].found is True and got["zz-repl"].version == ""
    assert "no version flag" in got["zz-repl"].error
    assert got["zz-hang"].found is True and got["zz-hang"].error.startswith("timeout")
    assert not marker.exists()


# ── domain readiness ─────────────────────────────────────────────────


AD_PROFILE = {"ad": ["bhce", "bhce-neo4j"], "c2-sliver": ["c2-sliver"], "reversing": ["ghidra-mcp"]}
ALL_SERVICES = ["bhce", "bhce-neo4j", "c2-sliver", "ghidra-mcp", "sandbox"]


def _statuses(missing: set[str] = frozenset()):
    specs = readiness.binaries()
    lines = [
        _line(s.binary, s.binary not in missing, f"/usr/bin/{s.binary}", "1.0")
        for s in specs
        if s.probed
    ]
    return readiness.parse_probe_output("\n".join(lines), specs)


def _domain(rows, name):
    return next(r for r in rows if r["domain"] == name)


def test_all_tools_and_services_present_is_ready():
    rows = readiness.domain_readiness(_statuses(), ALL_SERVICES, profile_services=AD_PROFILE)
    assert all(r["ready"] for r in rows), [r for r in rows if not r["ready"]]
    assert _domain(rows, "ad_operator")["status"] == "ready"


def test_missing_tool_is_degraded_and_named():
    rows = readiness.domain_readiness(
        _statuses({"nmap"}), ALL_SERVICES, profile_services=AD_PROFILE
    )
    recon = _domain(rows, "recon")
    assert recon["ready"] is False
    assert recon["missing_tools"] == ["nmap"]
    assert recon["status"] == "degraded (missing: nmap)"
    # A domain that does not use nmap stays ready.
    assert _domain(rows, "forensicator")["ready"] is True


def test_capability_with_one_of_its_binaries_present_is_not_missing():
    rows = readiness.domain_readiness(
        _statuses({"python"}), ALL_SERVICES, profile_services=AD_PROFILE
    )
    assert _domain(rows, "buggy")["ready"] is True


def test_missing_profile_service_is_not_available_with_profile_named():
    services = [s for s in ALL_SERVICES if s != "bhce"]
    rows = readiness.domain_readiness(_statuses(), services, profile_services=AD_PROFILE)
    ad = _domain(rows, "ad_operator")
    assert ad["ready"] is False
    assert ad["missing_services"] == ["bhce"]
    assert ad["status"] == "not available in this stack (needs profile ad)"
    assert _domain(rows, "recon")["ready"] is True


def test_tool_service_down_degrades_with_profile_named():
    services = [s for s in ALL_SERVICES if s not in {"c2-sliver", "ghidra-mcp"}]
    rows = readiness.domain_readiness(_statuses(), services, profile_services=AD_PROFILE)
    assert _domain(rows, "postexploit")["status"] == (
        "degraded (missing: sliver (needs profile c2-sliver))"
    )
    assert _domain(rows, "reverser")["status"] == (
        "degraded (missing: ghidra (needs profile reversing))"
    )


def test_unknown_running_services_never_reports_ready_for_a_profile():
    rows = readiness.domain_readiness(_statuses(), None, profile_services=AD_PROFILE)
    ad = _domain(rows, "ad_operator")
    assert ad["status"].startswith("not available") and "running services unknown" in ad["note"]


def test_compose_profiles_read_from_repo_compose():
    profiles = readiness.compose_profile_services(REPO / "docker-compose.yml")
    assert "bhce" in profiles["ad"]
    assert "ghidra-mcp" in profiles["reversing"]
    assert "sandbox" not in {s for names in profiles.values() for s in names}


# ── CLI ──────────────────────────────────────────────────────────────


@pytest.fixture
def compose_file(tmp_path):
    path = tmp_path / "compose.yml"
    path.write_text(
        "services:\n"
        "  sandbox: {}\n"
        "  bhce: {profiles: [ad]}\n"
        "  bhce-neo4j: {profiles: [ad]}\n"
        "  c2-sliver: {profiles: [c2-sliver]}\n"
        "  ghidra-mcp: {profiles: [reversing]}\n"
    )
    return path


def _cli(argv, *, missing=frozenset(), services=None, run=None):
    specs = readiness.binaries()
    executed: list[str] = []

    def execute(script: str) -> str:
        executed.append(script)
        return "\n".join(
            _line(s.binary, s.binary not in missing, f"/usr/bin/{s.binary}", "1.0")
            for s in specs
            if s.probed
        )

    out = io.StringIO()
    if services is not None:
        argv = [*argv, "--services", ",".join(services)]
    code = tools_cli.main(argv, stdout=out, execute=execute, run=run, specs=specs)
    return code, out.getvalue(), executed


def test_cli_json_shape(compose_file):
    code, text, executed = _cli(
        ["check", "--json", "--compose", str(compose_file)], services=ALL_SERVICES
    )
    assert code == 0 and len(executed) == 1
    payload = json.loads(text)
    assert set(payload) == {"running_services", "tools", "domains"}
    assert set(payload["tools"][0]) == {"binary", "capability", "found", "path", "version", "error"}
    row = payload["domains"][0]
    assert set(row) >= {"domain", "ready", "missing_tools", "missing_services", "note", "status"}
    assert {d["domain"] for d in payload["domains"]} == {d.name for d in readiness.DOMAINS}


def test_cli_domain_filter_and_table(compose_file):
    code, text, _ = _cli(
        ["check", "--domain", "ad_operator", "--compose", str(compose_file)],
        services=["sandbox"],
    )
    assert code == 0
    assert "ad_operator  not available in this stack (needs profile ad)" in text
    assert "recon" not in text.split("\n\n")[0]


def test_cli_require_exit_codes(compose_file):
    base = ["check", "--compose", str(compose_file)]
    assert _cli([*base, "--require", "recon"], services=ALL_SERVICES)[0] == 0
    assert _cli([*base, "--require", "recon"], missing={"nmap"}, services=ALL_SERVICES)[0] == 4
    assert _cli([*base, "--require", "ad_operator"], services=["sandbox"])[0] == 4
    # Not ready but not required: still exit 0.
    assert _cli(base, missing={"nmap"}, services=["sandbox"])[0] == 0
    assert _cli([*base, "--require", "no-such-domain"], services=ALL_SERVICES)[0] == 2


def test_cli_reads_running_services_from_docker_compose(compose_file):
    calls = []

    def run(argv):
        calls.append(list(argv))
        return 0, "sandbox\nbhce\nbhce-neo4j\n"

    code, text, _ = _cli(
        ["check", "--json", "--compose", str(compose_file), "--require", "ad_operator"], run=run
    )
    assert calls == [["docker", "compose", "ps", "--services", "--status", "running"]]
    assert code == 0 and json.loads(text)["running_services"] == ["bhce", "bhce-neo4j", "sandbox"]

    code, text, _ = _cli(
        ["check", "--json", "--compose", str(compose_file), "--require", "ad_operator"],
        run=lambda argv: (1, "no docker"),
    )
    assert code == 4 and json.loads(text)["running_services"] is None


def test_cli_script_prints_probe_script():
    out = io.StringIO()
    assert tools_cli.main(["script"], stdout=out) == 0
    assert out.getvalue() == readiness.probe_script(readiness.binaries())


def test_cli_dispatches_through_buggy_cli():
    from buggy.cli.__main__ import main as cli_main

    with pytest.raises(SystemExit) as exc:
        cli_main(["tools", "--help"])
    assert exc.value.code == 0


def test_toolspec_is_frozen():
    spec = readiness.binaries()[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.binary = "other"  # type: ignore[misc]


def test_planned_capability_is_probed_but_not_required():
    certipy = next(s for s in readiness.binaries() if s.binary == "certipy")
    assert certipy.lifecycle == Lifecycle.PLANNED.value
    rows = readiness.domain_readiness(
        _statuses({"certipy", "certipy-ad"}), ALL_SERVICES, profile_services=AD_PROFILE
    )
    assert _domain(rows, "ad_operator")["ready"] is True
