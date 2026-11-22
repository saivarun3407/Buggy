"""Tool and domain readiness: which declared tools run in this stack, per specialist.

Everything is derived from the capability registry
(``buggy_core.capabilities.CAPABILITY_REGISTRY``); there is no second tool list.

* :func:`binaries` turns the registry into one :class:`ToolSpec` per binary.
* :func:`probe_script` renders one POSIX shell script that, for each binary,
  resolves it on ``PATH`` and runs it with a version flag only (``--version``,
  then ``-V``), under ``timeout 5``, with stdin closed and no display. It never
  passes a target, URL, host or file. It prints one JSON line per binary.
* :func:`check` runs that script through an ``execute`` callable (production:
  the sandbox backend's ``execute``; tests: a fake) and parses the lines.
* :func:`domain_readiness` folds tool status and the running compose services
  into one verdict per agent role: ``ready``, ``degraded (missing: ...)`` or
  ``not available in this stack (needs profile X)``.

Standard library, ``buggy_core`` and ``pyyaml`` only, so it imports in the slim
operator image.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from buggy_core.capabilities import CAPABILITY_REGISTRY, Capability, Lifecycle

#: Flags tried, in order. Only these ever follow a binary in the probe script.
VERSION_FLAGS: tuple[str, ...] = ("--version", "-V")
#: Seconds each version invocation may run before ``timeout`` stops it.
PROBE_TIMEOUT_SECONDS = 5
#: Version lines are cut to this many characters.
VERSION_MAX_CHARS = 200

#: Lifecycles whose binaries are probed. Quarantined/deprecated ones are not.
PROBED_LIFECYCLES = frozenset({Lifecycle.SUPPORTED, Lifecycle.PREVIEW, Lifecycle.PLANNED})
#: Lifecycles a domain *requires*. Planned tools are reported, never required.
REQUIRED_LIFECYCLES = frozenset({Lifecycle.SUPPORTED, Lifecycle.PREVIEW})
#: Deliveries a domain requires: in the image (``base``) or behind a profile.
#: ``pip`` (installed by the agent at run time) and ``external`` are optional.
_REQUIRED_DELIVERY_PREFIXES = ("base", "profile:", "sidecar")

# A binary name is interpolated into the script; anything else is refused.
_SAFE_BINARY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


@dataclass(frozen=True)
class Domain:
    """What one agent role needs: registry categories and compose profiles.

    ``categories`` select tools from the registry (no tool names here);
    ``profiles`` are compose profiles whose services must all be running.
    """

    name: str
    categories: tuple[str, ...]
    profiles: tuple[str, ...] = ()


# Agent role -> registry categories (and compose profiles) it works with. Keys
# cover every role in ``graph_registry.STANDARD_GRAPHS`` and
# ``capabilities.ROLE_CAPABILITY_POLICY``; a test keeps them in step.
DOMAINS: tuple[Domain, ...] = (
    Domain("buggy", ("runtime",)),
    Domain("recon", ("runtime", "recon", "web", "tls")),
    Domain("soundwave", ("runtime",)),
    Domain("exploit", ("runtime", "web", "vuln", "exploit", "credentials")),
    Domain("postexploit", ("runtime", "credentials", "smb", "tunneling", "c2", "network")),
    Domain("analyst", ("runtime",)),
    Domain("asvs_assessor", ("runtime", "web", "tls")),
    Domain("reverser", ("runtime", "reversing", "fuzzing")),
    Domain("contract_auditor", ("runtime",)),
    Domain("cloud_hunter", ("runtime", "recon", "secrets")),
    Domain("ad_operator", ("runtime", "ad", "smb", "credentials"), profiles=("ad",)),
    Domain("blue_cell", ("runtime", "network", "dfir")),
)


@dataclass(frozen=True)
class ToolSpec:
    """One binary of one registry capability."""

    name: str
    """Capability id (``impacket``, ``nmap``)."""
    binary: str
    capability: str
    domains: tuple[str, ...]
    category: str = ""
    delivery: str = "base"
    lifecycle: str = Lifecycle.SUPPORTED.value
    requires_service: str | None = None
    requires_profile: str | None = None

    @property
    def probed(self) -> bool:
        """True when the binary is looked for inside the sandbox."""
        return self.delivery == "base" or self.delivery.startswith(("profile:", "pip"))


@dataclass(frozen=True)
class ToolStatus:
    """Probe result for one binary. ``found`` is ``None`` when it was not probed."""

    binary: str
    capability: str
    found: bool | None
    path: str = ""
    version: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── tool list (derived from the registry) ────────────────────────────


def _domains_for(cap: Capability, domains: Sequence[Domain]) -> tuple[str, ...]:
    return tuple(
        d.name
        for d in domains
        if cap.category in d.categories and (not cap.roles or d.name in cap.roles)
    )


def binaries(
    registry: Iterable[Capability] | None = None,
    domains: Sequence[Domain] = DOMAINS,
) -> list[ToolSpec]:
    """One :class:`ToolSpec` per binary of every probed-lifecycle capability."""
    out: list[ToolSpec] = []
    seen: set[str] = set()
    for cap in CAPABILITY_REGISTRY if registry is None else registry:
        if cap.lifecycle not in PROBED_LIFECYCLES:
            continue
        for binary in cap.binaries:
            if binary in seen:
                continue
            seen.add(binary)
            out.append(
                ToolSpec(
                    name=cap.id,
                    binary=binary,
                    capability=cap.id,
                    domains=_domains_for(cap, domains),
                    category=cap.category,
                    delivery=cap.delivery,
                    lifecycle=cap.lifecycle.value,
                    requires_service=cap.requires_service,
                    requires_profile=cap.requires_profile,
                )
            )
    return out


# ── probe script ─────────────────────────────────────────────────────


def _q(value: str) -> str:
    """Single-quote ``value`` for POSIX sh (only safe binary names reach here)."""
    return "'" + value.replace("'", "'\\''") + "'"


_SCRIPT_HEADER = f"""\
#!/bin/sh
# buggy readiness probe: version flags only, never a target, URL, host or file.
unset DISPLAY WAYLAND_DISPLAY
LC_ALL=C
export LC_ALL
_esc() {{
  printf '%s' "$1" | tr -d '\\000-\\037' | cut -c1-{VERSION_MAX_CHARS} \\
    | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g'
}}
_emit() {{
  printf '{{"binary": "%s", "found": %s, "path": "%s", "version": "%s", "error": "%s"}}\\n' \\
    "$(_esc "$1")" "$2" "$(_esc "$3")" "$(_esc "$4")" "$(_esc "$5")"
}}
_first() {{
  printf '%s\\n' "$1" | sed -e '/^[[:space:]]*$/d' | head -n 1
}}
if command -v timeout >/dev/null 2>&1; then _T=1; else _T=0; fi
"""


def _probe_block(binary: str) -> str:
    """Shell for one binary: resolve, then each version flag under ``timeout``."""
    b = _q(binary)
    t = PROBE_TIMEOUT_SECONDS
    lines = [
        f"p=$(command -v {b} 2>/dev/null) || p=''",
        "v=''; e=''",
        'if [ -z "$p" ]; then',
        f"  _emit {b} false '' '' 'not found'",
        'elif [ "$_T" = 0 ]; then',
        f"  _emit {b} true \"$p\" '' 'not run: no timeout command in the sandbox'",
        "else",
        "  rc=1",
    ]
    for flag in VERSION_FLAGS:
        lines += [
            '  if [ -z "$v" ] && [ -z "$e" ]; then',
            f"    o=$(timeout -k 1 {t} {b} {flag} 2>&1 <&-)",
            "    rc=$?",
            '    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then',
            f"      e='timeout after {t}s'",
            '    elif [ "$rc" = 0 ]; then',
            '      v=$(_first "$o")',
            "    fi",
            "  fi",
        ]
    lines += [
        '  if [ -z "$v" ] && [ -z "$e" ]; then e="no version flag answered (exit $rc)"; fi',
        f'  _emit {b} true "$p" "$v" "$e"',
        "fi",
    ]
    return "\n".join(lines) + "\n"


def probe_script(specs: Sequence[ToolSpec]) -> str:
    """One POSIX sh script printing one JSON line per probed binary.

    Each binary is run only as ``timeout -k 1 5 <bin> <flag>`` with ``<flag>``
    in :data:`VERSION_FLAGS`, stdin closed (``<&-``) and ``DISPLAY`` unset, so
    a tool that would open a GUI, a REPL or a listener without arguments is
    never started that way. Raises ``ValueError`` for an unsafe binary name.
    """
    parts = [_SCRIPT_HEADER]
    seen: set[str] = set()
    for spec in specs:
        if not spec.probed or spec.binary in seen:
            continue
        if not _SAFE_BINARY.match(spec.binary):
            raise ValueError(f"refusing unsafe binary name {spec.binary!r}")
        seen.add(spec.binary)
        parts.append(_probe_block(spec.binary))
    return "".join(parts)


def parse_probe_output(output: str, specs: Sequence[ToolSpec]) -> list[ToolStatus]:
    """One :class:`ToolStatus` per spec, from the script's JSON lines.

    A probed binary with no line in ``output`` (truncated output, the script
    killed) is ``found=None`` with an error; a sidecar or external tool is
    ``found=None`` with a note, since it is not a binary in the sandbox.
    """
    seen: dict[str, dict[str, Any]] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("binary"), str):
            seen[row["binary"]] = row
    statuses: list[ToolStatus] = []
    for spec in specs:
        if not spec.probed:
            statuses.append(
                ToolStatus(
                    spec.binary,
                    spec.capability,
                    None,
                    error=f"not a sandbox binary (delivery {spec.delivery})",
                )
            )
            continue
        row = seen.get(spec.binary)
        if row is None:
            statuses.append(ToolStatus(spec.binary, spec.capability, None, error="no probe output"))
            continue
        statuses.append(
            ToolStatus(
                binary=spec.binary,
                capability=spec.capability,
                found=bool(row.get("found")),
                path=str(row.get("path") or ""),
                version=str(row.get("version") or ""),
                error=str(row.get("error") or ""),
            )
        )
    return statuses


def check(
    execute: Callable[[str], str], specs: Sequence[ToolSpec] | None = None
) -> list[ToolStatus]:
    """Run :func:`probe_script` through ``execute`` and parse what comes back."""
    specs = binaries() if specs is None else list(specs)
    return parse_probe_output(execute(probe_script(specs)), specs)


# ── compose profiles ─────────────────────────────────────────────────


def compose_profile_services(compose: Mapping[str, Any] | str | Path) -> dict[str, list[str]]:
    """``{profile: [service, ...]}`` from a compose document or file path."""
    if isinstance(compose, (str, Path)):
        import yaml

        compose = yaml.safe_load(Path(compose).read_text(encoding="utf-8")) or {}
    out: dict[str, list[str]] = {}
    for name, service in (compose.get("services") or {}).items():
        for profile in (service or {}).get("profiles") or ():
            out.setdefault(str(profile), []).append(str(name))
    return {profile: sorted(names) for profile, names in out.items()}


# ── domain readiness ─────────────────────────────────────────────────


def _required(spec: ToolSpec) -> bool:
    return spec.lifecycle in {lc.value for lc in REQUIRED_LIFECYCLES} and spec.delivery.startswith(
        _REQUIRED_DELIVERY_PREFIXES
    )


def _profile_of(service: str, profile_services: Mapping[str, Sequence[str]]) -> str | None:
    for profile, names in profile_services.items():
        if service in names:
            return profile
    return None


def domain_readiness(
    tool_status: Sequence[ToolStatus],
    running_services: Iterable[str] | None,
    *,
    profile_services: Mapping[str, Sequence[str]] | None = None,
    specs: Sequence[ToolSpec] | None = None,
    domains: Sequence[Domain] = DOMAINS,
) -> list[dict[str, Any]]:
    """One verdict per domain.

    * A domain profile whose services are not all running (or whose services
      are unknown) -> ``not available in this stack (needs profile X)``.
    * Otherwise a required capability with none of its binaries found, or whose
      own service is not running -> ``degraded (missing: ...)``.
    * Otherwise ``ready``.

    ``running_services=None`` means the running services could not be read:
    every service requirement is then unmet and the note says so.
    """
    specs = binaries(domains=domains) if specs is None else list(specs)
    profile_services = dict(profile_services or {})
    running = set(running_services or ())
    found_by_binary = {s.binary: s.found for s in tool_status}

    caps: dict[str, list[ToolSpec]] = {}
    for spec in specs:
        caps.setdefault(spec.capability, []).append(spec)

    out: list[dict[str, Any]] = []
    for domain in domains:
        notes: list[str] = []
        missing_services: list[str] = []
        unmet_profiles: list[str] = []
        for profile in domain.profiles:
            services = list(profile_services.get(profile, ()))
            if not services:
                unmet_profiles.append(profile)
                notes.append(f"no services known for profile {profile!r}")
                continue
            gone = [s for s in services if s not in running]
            if gone:
                unmet_profiles.append(profile)
                missing_services.extend(gone)

        missing_tools: list[str] = []
        for cap_id, cap_specs in caps.items():
            first = cap_specs[0]
            if domain.name not in first.domains or not _required(first):
                continue
            service = first.requires_service
            if service and service not in running:
                profile = first.requires_profile or _profile_of(service, profile_services)
                needs = f"profile {profile}" if profile else f"service {service}"
                missing_tools.append(f"{cap_id} (needs {needs})")
                continue
            if first.delivery == "sidecar":
                continue  # its service is running; there is no sandbox binary
            if not any(found_by_binary.get(s.binary) for s in cap_specs):
                unknown = all(found_by_binary.get(s.binary) is None for s in cap_specs)
                missing_tools.append(f"{cap_id} (no probe result)" if unknown else cap_id)

        if running_services is None:
            notes.append("running services unknown")
        if unmet_profiles:
            status = "not available in this stack (needs profile " + ", ".join(unmet_profiles) + ")"
        elif missing_tools:
            status = "degraded (missing: " + ", ".join(missing_tools) + ")"
        else:
            status = "ready"
        out.append(
            {
                "domain": domain.name,
                "ready": status == "ready",
                "status": status,
                "missing_tools": missing_tools,
                "missing_services": sorted(set(missing_services)),
                "profiles": list(domain.profiles),
                "note": "; ".join(notes),
            }
        )
    return out
