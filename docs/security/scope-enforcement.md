# Scope enforcement

How Buggy keeps an agent inside the engagement's authorised scope, and what
each layer does and does not guarantee.

## The three trees

Every engagement has files at the same relative path under three roots. The
roots differ in who can write them (`packages/buggy/buggy/middleware/_control.py`).

| Root | Host path | Written by | sandbox | langgraph |
|---|---|---|---|---|
| workspace | `$BUGGY_HOME/workspace/<engagement>` | the agent | read-write | read-only |
| control | `$BUGGY_HOME/control/<engagement>` | the operator | read-only | read-only |
| audit | `$BUGGY_HOME/audit/<engagement>` | langgraph, egress guard | not mounted | read-write |

- `control/<engagement>/roe.json` is the **enforced scope**.
- `control/<engagement>/approvals/decisions.jsonl` holds human approvals.
- `audit/<engagement>/roe-decisions.jsonl` is the RoE decision ledger.
- `audit/<engagement>/approvals/requests.jsonl` holds the agent's approval requests.
- `audit/egress-guard/egress-decisions.jsonl` is the network drop ledger.
- `workspace/<engagement>/plan/roe.json` is a **draft** the agent may write. It
  has no effect until an operator promotes it.

The operator writes the control root from the host, or from the one-off
`operator` compose service:

```bash
docker compose --profile operator run --rm operator buggy-cli scope show <engagement>
```

```bash
docker compose --profile operator run --rm operator buggy-cli scope approve <engagement>
```

`buggy hunt` and `buggy-cli engage` write the enforced scope directly, because
the operator typed the targets. `buggy-cli scope approve` validates a draft
with the same parser the guardrail uses and refuses an enforce-mode policy with
an empty `in_scope`.

## Layers

### 1. Command parser (advisory)

`RoEGuardrailMiddleware` reads the enforced `roe.json` on every tool call and
refuses commands whose literal targets are out of scope. It is a fast,
readable refusal for the model. It cannot see a target that is built at run
time (`h=$(...); curl $h`), so it is not the boundary.

`BUGGY_ROE_REQUIRE` defaults to on: with no enforced `roe.json`, every gated
tool is refused. Set `BUGGY_ROE_REQUIRE=0` only for local labs.

### 2. Egress guard (authoritative)

The `egress-guard` service is the sandbox's only route to a target.

- `sandbox-net` is a Docker `internal` network. Docker drops every packet on it
  whose destination is outside its subnet, whatever the sandbox does with raw
  sockets or routes.
- The sandbox entrypoint builds a VXLAN tunnel to the guard and makes it the
  default route. Target traffic is addressed to the guard, so it passes
  Docker's filter, and arrives at the guard carrying its real destination.
- The guard forwards a tunnelled packet only if the engagement's policy allows
  the destination. Its DNS proxy answers only in-scope names, and adds the
  addresses it returned to the allow set for the record's TTL.
- Networks the guard is attached to (the management plane) are never reachable
  through it, in any mode, unless listed in `BUGGY_GUARD_LOCAL_TARGET_CIDRS`
  (lab overlays).
- Until langgraph pushes a policy the guard forwards nothing and resolves
  nothing.

Why the agent cannot change it:

- The rules are in the guard's network namespace, not the sandbox's.
- The entrypoint removes `CAP_NET_ADMIN` (and `CAP_SETPCAP`) from the
  capability bounding set before the daemon starts; no child process can get
  them back.
- The guard's control API listens only on the management network. From the
  sandbox side the guard accepts DNS and the tunnel, nothing else.
- The control token (`EGRESS_GUARD_TOKEN`) is given to langgraph and the guard
  only.

### 3. Fail closed

- Provisioning failure raises `EgressProvisioningError` from `before_agent`:
  the run aborts before any tool runs. The same check runs before every gated
  tool call, so a scope edit reaches the guard on the next call.
- When RoE is required and the audit ledger cannot be written, gated tools are
  refused (`AUDIT_UNAVAILABLE`).
- The sandbox daemon will not start without `SANDBOX_TOKEN`.
- `docker-compose.yml` will not render without `SANDBOX_TOKEN` and
  `EGRESS_GUARD_TOKEN`. `buggy onboard`, `buggy start` and
  `scripts/ensure-stack-secrets.sh` generate them.

## Audit records

Both ledgers are hash-chained JSONL, optionally HMAC-bound with
`BUGGY_AUDIT_HMAC_KEY`:

```bash
buggy-cli audit ~/.buggy/audit/<engagement>/roe-decisions.jsonl
```

```bash
buggy-cli audit ~/.buggy/audit/egress-guard/egress-decisions.jsonl
```

Guard events: `guard_started`, `policy_applied`, `dns_refused`,
`dns_answer_denied`, `egress_drop` (destination address, protocol, port,
packet count, policy digest).

## Verification

```bash
make e2e-scope
```

`packages/buggy/tests/e2e/test_scope_enforcement_e2e.py` starts
`docker-compose.yml`'s `egress-guard` and `sandbox` services plus two local
targets and drives the shipped middleware against them. It asserts that:

- nothing leaves before a policy is provisioned;
- an in-scope request succeeds;
- an out-of-scope request the parser can see is refused before execution;
- an out-of-scope request assembled at run time (by name and by address)
  executes, is dropped at the network, and appears in the drop ledger;
- `nft`, route and link changes fail inside the sandbox;
- the direct path and the guard's control API are unreachable from the sandbox;
- a wrong token or unreachable guard aborts the run;
- both ledgers verify, and the sandbox cannot write the control root or see
  the audit root.

By default the test swaps the Kali sandbox image for
`containers/sandbox-e2e.Dockerfile`, which runs the same entrypoint and daemon
code. Set `BUGGY_E2E_SANDBOX_IMAGE=buggy-sandbox:stable` to run it against the
full image.

## Blocking the sandbox's network entirely

`machine_enforcement.sandbox_egress: "blocked"` gives the sandbox no route to
any target: the guard is loaded with an empty allowlist (the search-provider
hosts stay reachable), and the guardrail refuses a shell command aimed at a
target with `SANDBOX_NETWORK_BLOCKED`, naming the tools to use instead.
Targets are then reached only by the evidence gateway, the scoped browser and
the pipeline, which is the only place a state-changing request can be held
for approval. `buggy hunt` and `scope import` set it by default;
`--allow-sandbox-network` / `--lab` turn it off.

## Addresses on the sandbox network

The guard and the sandbox have fixed addresses. Docker assigns every other
service on `sandbox-net` from `BUGGY_SANDBOX_IP_RANGE` (default the upper
half of the subnet), so no service can be handed one of the fixed addresses
first.

## Known limits

- Containers on `sandbox-net` (neo4j, langgraph, ghidra-mcp, c2-sliver) are
  reachable from the sandbox directly; that is the management link, not a path
  out. Dual-homed services other than the guard set `net.ipv4.ip_forward=0`.
- The host's address on `sandbox-net` is reachable from the sandbox, as on any
  Docker bridge. Do not bind host services to `0.0.0.0` on an operator machine.
- `docker-compose.tun.yml` keeps `CAP_NET_ADMIN` in the sandbox for Layer-3
  pivots. The guard and Docker's internal-network filter still apply.
- The deterministic pipeline (Phase 2) runs in its own container and filters
  scope in code; it does not go through this guard.
- `*` in a scope rule covers one DNS label (`*.acme.com` does not match
  `a.b.acme.com`); `**.acme.com` covers any depth. Neither covers the apex.
  The guardrail and the guard implement this separately (the guard image has
  no `buggy_core`); a test pins them to the same answers.
- Deployments without the guard (`BUGGY_EGRESS_GUARD_URL` unset) fall back to
  the in-sandbox nftables applier. That applier is advisory against a hostile
  agent; a failure to apply it still aborts the run.
