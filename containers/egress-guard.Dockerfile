# Egress guard - the sandbox's network boundary (see
# packages/buggy/buggy/egress_guard/__init__.py and docs/security/scope-enforcement.md).
#
# Deliberately tiny: Alpine + nftables + iproute2 + the Python standard
# library. No agent code, no third-party Python packages, no shell tooling the
# agent could use even if it reached this container (it cannot: the sandbox
# has no route to anything here except DNS).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache python3 nftables iproute2

# BUGGY_SKIP_BOOT keeps ``buggy/__init__.py`` from importing the framework,
# which this image does not ship (same convention as the sandbox image).
ENV PYTHONPATH=/opt \
    PYTHONUNBUFFERED=1 \
    BUGGY_SKIP_BOOT=1

COPY packages/buggy/buggy/__init__.py /opt/buggy/__init__.py
COPY packages/buggy/buggy/egress_guard /opt/buggy/egress_guard

HEALTHCHECK --interval=5s --timeout=3s --retries=12 --start-period=5s \
    CMD ["python3", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % (os.environ.get('BUGGY_GUARD_CONTROL_PORT') or '9440'), timeout=2)"]

ENTRYPOINT ["python3", "-m", "buggy.egress_guard"]
