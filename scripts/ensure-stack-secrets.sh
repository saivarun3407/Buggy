#!/usr/bin/env bash
# Ensure the stack's required secrets exist in an env file.
#
# docker-compose.yml refuses to render without SANDBOX_TOKEN and
# EGRESS_GUARD_TOKEN: the sandbox daemon will not start unauthenticated and
# the egress guard's control API has no anonymous mode. `buggy onboard`
# generates both; this script does the same for `make dev` / bare compose
# use. Existing values are never changed.
#
# Usage: scripts/ensure-stack-secrets.sh [path/to/.env]   (default: ./.env)
set -euo pipefail

env_file="${1:-.env}"
touch "$env_file"
chmod 600 "$env_file" 2>/dev/null || true

random_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

ensure() {
    local name="$1"
    if grep -Eq "^${name}=.+" "$env_file"; then
        return 0
    fi
    # Drop an empty assignment so the appended line is the only definition.
    if grep -Eq "^${name}=" "$env_file"; then
        local tmp
        tmp="$(mktemp)"
        grep -Ev "^${name}=" "$env_file" >"$tmp" || true
        cat "$tmp" >"$env_file"
        rm -f "$tmp"
    fi
    printf '%s=%s\n' "$name" "$(random_hex)" >>"$env_file"
    echo "generated ${name} in ${env_file}"
}

ensure SANDBOX_TOKEN
ensure EGRESS_GUARD_TOKEN
ensure BUGGY_AUDIT_HMAC_KEY
