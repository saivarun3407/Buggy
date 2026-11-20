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

Measured on 2026-11-20 by running the generated probe script inside the
locally built `buggy-sandbox:stable` image (Kali rolling, the pinned digest in
`containers/sandbox.Dockerfile`), with no network and with the capability set
the sandbox has at run time (`NET_RAW`, `NET_BIND_SERVICE`, `SYS_PTRACE`,
`SETUID`, `SETGID`; `NET_ADMIN` dropped). Only the `sandbox` service was
counted as running, so domains that need another profile show that.

```
buggy-cli tools script > probe.sh
docker run --rm -i --network none --cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
    --cap-add SYS_PTRACE --cap-add SETUID --cap-add SETGID --entrypoint sh buggy-sandbox:stable \
    < probe.sh > probe.jsonl
buggy-cli tools check --probe-output probe.jsonl --services sandbox --compose docker-compose.yml
```

```
buggy                  ready
recon                  ready
soundwave              ready
exploit                ready
postexploit            degraded (missing: sliver (needs profile c2-sliver))
analyst                ready
asvs_assessor          ready
reverser               degraded (missing: ghidra (needs profile reversing))
contract_auditor       ready
cloud_hunter           ready
ad_operator            not available in this stack (needs profile ad)
blue_cell              ready
phisher                ready
mobile_operator        degraded (missing: ghidra (needs profile reversing))
wireless_operator      ready
osint_operator         ready
iot_operator           degraded (missing: ghidra (needs profile reversing))
ics_operator           ready
forensicator           ready
supply_chain_operator  ready

binaries: 86 found, 4 missing, 1 not probed
```

What the numbers mean, and what they do not:

- **86 of 90 declared binary names are on PATH.** The four absent names are
  `sliver` (it ships in the `c2-sliver` profile's own service) and three
  alternate names of tools that are present under another name: `ncat` (`nc`
  is installed), `certipy` (`certipy-ad` is installed) and `python`
  (`python3` is installed). No declared capability is missing its tool.
- **48 answered `--version` or `-V`.** 37 are present but answer neither flag
  (they use `-v`, `version` or print usage), and `msfconsole` did not answer
  within 5 seconds. "Present" is all this check proves for those; it does not
  run any tool against a target.
- **"ready" means every tool the role needs is present and its services are
  running.** It says nothing about how well that role performs. Only the web
  and API path has lab tests and a coverage audit
  (`benchmark/lab/results/coverage.md`); the other domains are inherited
  breadth that has been checked for presence, not for results.
- This run found one real fault, since fixed: `nmap` could not start at all in
  the hardened sandbox, because its file capabilities include `cap_net_admin`,
  which the sandbox drops. `tests/test_sandbox_tools_start.py` now pins it.
