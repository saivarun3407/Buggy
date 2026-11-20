# Tool and domain readiness

Buggy declares a wide specialist roster (AD, C2, reversing, mobile, DFIR...). A
declared tool is a claim until it has been seen running in *this* stack.
`buggy-cli tools check` checks every declared tool inside the sandbox and reports,
per specialist domain, whether that domain can work right now.

## What it checks

- **Tools.** The list comes from the capability registry
  (`packages/buggy-core/buggy_core/capabilities.py`); there is no second list. Every
  binary of a supported, preview or planned capability is resolved on `PATH` in the
  sandbox and run as `<binary> --version`, then `<binary> -V` if the first gave no
  answer. Nothing else is ever run: no target, URL, host or file argument. Each
  call runs under `timeout 5`, with stdin closed and `DISPLAY` unset, so a tool that
  opens a GUI, a listener or a REPL when run without arguments is never started that
  way. Sidecar tools (Ghidra) are not sandbox binaries; they count as present when
  their service is running.
- **Services.** The compose services that are running (`docker compose ps`, or
  `--services a,b`) against the profiles in `docker-compose.yml`.
- **Domains.** One per agent role (`buggy/readiness.py::DOMAINS`). A domain names
  registry *categories* and compose *profiles*, never tool names. Only supported or
  preview tools delivered in the image, behind a profile or as a sidecar are
  required; planned and `pip` tools are reported but never required.

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| `ready` | every required tool answered and every required service is running |
| `degraded (missing: x, y)` | the domain works, without the named capabilities. `sliver (needs profile c2-sliver)` means the binary is there but its service is not running |
| `not available in this stack (needs profile ad)` | a profile the domain depends on is not running (for `ad_operator`: the BloodHound CE services) |

`(no probe result)` after a name means the probe printed nothing for that binary
(output truncated or the script stopped); it is reported as missing, not as present.
`note: running services unknown` means `docker compose ps` could not be read, so no
service requirement counts as met.

Per binary, `--json` gives `found`, `path`, the first line of the version output
and an `error`: `not found`, `timeout after 5s`, or `no version flag answered
(exit N)` (the binary exists but answers neither flag; it is still `found`).

## Running it

```sh
buggy-cli tools check                       # table, probe through SANDBOX_URL
buggy-cli tools check --json                # {"running_services", "tools", "domains"}
buggy-cli tools check --domain ad_operator
buggy-cli tools check --require recon       # exit 4 when recon is not ready

# From the host, when the sandbox daemon is not reachable directly:
buggy-cli tools script > probe.sh
docker compose exec -T sandbox sh < probe.sh > probe.jsonl
buggy-cli tools check --probe-output probe.jsonl
```

The exit code is 0 unless `--require DOMAIN` is given and that domain is not ready
(4); an unknown domain name exits 2.

## Matrix for this repo's Kali sandbox image

<!-- PLACEHOLDER: to be filled by the integrator from a real run of
     `buggy-cli tools check` against the built sandbox image. Nothing below has
     been measured yet; do not read it as a result. -->

**Not yet measured.** This section is a placeholder. The integrator replaces it with
the output of a real `buggy-cli tools check` run against the built sandbox image,
stating the image tag, the date and the profiles that were running.
