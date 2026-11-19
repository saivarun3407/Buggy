#!/bin/bash
# Make /workspace world-accessible so the host user can read findings,
# reports, and engagement files without sudo.
# Security boundary is the container itself, not file permissions.
chmod -R 777 /workspace 2>/dev/null || true
# Ensure all NEW files are also world-readable/writable
umask 0000

# ── Network boundary hand-off ─────────────────────────────────────────
# With BUGGY_EGRESS_GATEWAY set (the compose default) this container sits on
# a Docker ``internal`` network: Docker drops every packet whose destination
# is outside that subnet, so there is no route out at all. The only path to a
# target is a VXLAN tunnel to the egress-guard sidecar, which filters by the
# engagement's RoE in its own network namespace.
#
# The tunnel and default route are installed here, then CAP_NET_ADMIN is
# removed from the capability bounding set before anything the agent controls
# is started (CAP_SETPCAP, needed only to perform that drop, goes with it). A
# bounding-set drop cannot be undone by any descendant process, root or not,
# so the agent can neither change the route nor load firewall rules.
#
# Every step is fail-closed: if one fails the container exits instead of
# starting a sandbox whose network boundary is not in place.
DROP_NET_ADMIN=0
if [ -n "${BUGGY_EGRESS_GATEWAY:-}" ]; then
    gw="${BUGGY_EGRESS_GATEWAY}"
    tun_if="bgtun0"
    tun_local="${BUGGY_TUNNEL_LOCAL:-10.254.250.2/30}"
    tun_peer="${BUGGY_TUNNEL_PEER:-10.254.250.1}"
    vni="${BUGGY_TUNNEL_VNI:-4242}"
    route_line="$(ip -4 -o route get "${gw}" 2>/dev/null | head -n1)"
    dev="$(printf '%s\n' "${route_line}" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
    src="$(printf '%s\n' "${route_line}" | sed -n 's/.* src \([^ ]*\).*/\1/p')"
    if [ -z "${dev}" ] || [ -z "${src}" ]; then
        echo "FATAL: egress guard ${gw} is not reachable on any interface" >&2
        exit 70
    fi
    ip link del "${tun_if}" 2>/dev/null || true
    if ! ip link add "${tun_if}" type vxlan id "${vni}" local "${src}" remote "${gw}" \
            dstport 4789 dev "${dev}" \
        || ! ip addr add "${tun_local}" dev "${tun_if}" \
        || ! ip link set "${tun_if}" mtu 1400 up \
        || ! ip route replace default via "${tun_peer}" dev "${tun_if}"; then
        echo "FATAL: cannot route sandbox egress through guard ${gw}" >&2
        exit 70
    fi
    # BUGGY_SANDBOX_KEEP_NET_ADMIN=1 (set only by docker-compose.tun.yml)
    # keeps the capability for Layer-3 pivot tooling. The boundary itself does
    # not depend on the drop: the guard's rules and Docker's internal-network
    # filter are both outside this container's network namespace.
    if [ "${BUGGY_SANDBOX_KEEP_NET_ADMIN:-0}" != "1" ]; then
        DROP_NET_ADMIN=1
    fi
fi

run() {
    if [ "${DROP_NET_ADMIN}" = "1" ]; then
        if ! command -v capsh >/dev/null 2>&1; then
            echo "FATAL: capsh missing; cannot drop CAP_NET_ADMIN" >&2
            exit 71
        fi
        exec capsh --drop=cap_net_admin,cap_setpcap -- -c 'exec "$@"' sandbox "$@"
    fi
    exec "$@"
}

# HTTP daemon mode (default ON). The container runs the FastAPI sandbox
# server on ``localhost:9999`` for every deployment target — dev,
# local-docker, GCE Spot VMs, and Cloud Run multi-container. The agent
# process (HTTPSandbox in buggy/backends/http_sandbox.py) talks to
# it over HTTP. The previous default of ``0`` (tail -f keep-alive) is
# kept as an opt-out for legacy ``docker exec`` workflows: set
# ``SANDBOX_DAEMON=0`` to disable the daemon.
if [ "${SANDBOX_DAEMON:-1}" = "1" ]; then
    run python3 -m buggy.sandbox_server
fi

run "$@"
