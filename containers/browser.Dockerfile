# syntax=docker/dockerfile:1.7
#
# Scoped browser: Playwright Chromium behind an MCP server. Every request the
# page makes is checked against the engagement's enforced scope before it
# leaves the container (buggy.scoped_browser). The agent never drives this
# browser directly; it calls the MCP tools from the langgraph process.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    PYTHONPATH=/opt \
    PYTHONUNBUFFERED=1 \
    BUGGY_SKIP_BOOT=1 \
    BUGGY_CONTROL_ROOT=/control \
    BUGGY_AUDIT_ROOT=/audit

RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then \
        export PIP_CERT=/run/secrets/extra_ca NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; \
        printf 'Acquire::https::CaInfo "/run/secrets/extra_ca";\n' > /etc/apt/apt.conf.d/99extra-ca; \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates libatomic1 \
    && pip install --no-cache-dir \
        "pydantic>=2.0.0" "pydantic-settings>=2.0.0" "mcp>=1.9.0,<2" "playwright==1.65.2" \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99extra-ca

COPY packages/buggy/buggy/__init__.py /opt/buggy/__init__.py
COPY packages/buggy/buggy/pipeline /opt/buggy/pipeline
COPY packages/buggy/buggy/capture /opt/buggy/capture
COPY packages/buggy/buggy/egress_guard /opt/buggy/egress_guard
COPY packages/buggy/buggy/scoped_browser /opt/buggy/scoped_browser
COPY packages/buggy-core/buggy_core /opt/buggy_core

ENTRYPOINT ["python", "-m", "buggy.scoped_browser.mcp_server"]
