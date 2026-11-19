# Deterministic recon pipeline (packages/buggy/buggy/pipeline).
#
# Runs the scanners as plain subprocesses and serves their output read-only
# over MCP. There is no LLM client, agent framework or model credential in
# this image.
#
# Tool versions are NOT written here: the build reads them from
# buggy/pipeline/versions.py, installs exactly those, and records the SHA-256
# of each resulting binary in /opt/buggy/pipeline-tools.json. At run time the
# pipeline refuses a binary whose hash differs from that manifest.

#
# PYTHON_IMAGE / GOLANG_IMAGE let a build pull the bases from a registry
# mirror. Optional build secret ``extra_ca``: a PEM bundle to trust during the
# build (TLS-inspecting CI proxies); it is not kept in the image.
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
ARG GOLANG_IMAGE=golang:1.26-bookworm

# ── 1. the install plan, from the single source of truth ──────────────
FROM ${PYTHON_IMAGE} AS plan
ENV BUGGY_SKIP_BOOT=1 PYTHONPATH=/opt
COPY packages/buggy/buggy/__init__.py /opt/buggy/__init__.py
COPY packages/buggy/buggy/pipeline/__init__.py packages/buggy/buggy/pipeline/versions.py /opt/buggy/pipeline/
RUN python -m buggy.pipeline.versions --install-plan > /install-plan.txt \
    && python -m buggy.pipeline.versions --nuclei-templates > /nuclei-templates.txt

# ── 2. build the pinned scanners ──────────────────────────────────────
FROM ${GOLANG_IMAGE} AS tools
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then \
        printf 'Acquire::https::CaInfo "/run/secrets/extra_ca";\n' > /etc/apt/apt.conf.d/99extra-ca; \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99extra-ca
COPY --from=plan /install-plan.txt /install-plan.txt
ENV CGO_ENABLED=1 GOFLAGS=-trimpath
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi \
    && while read -r module; do echo "go install ${module}" && go install "${module}" || exit 1; done \
    < /install-plan.txt

# ── 3. runtime ────────────────────────────────────────────────────────
FROM ${PYTHON_IMAGE}
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then \
        printf 'Acquire::https::CaInfo "/run/secrets/extra_ca";\n' > /etc/apt/apt.conf.d/99extra-ca; \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates git libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99extra-ca

# pydantic(-settings): imported by buggy_core, whose RoE types the scope filter
# shares with the guardrail. PyYAML: OpenAPI documents served as YAML.
# mcp: the read-only query server.
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi \
    && pip install --no-cache-dir \
    "pydantic>=2.0.0" "pydantic-settings>=2.0.0" "pyyaml>=6.0.0" "mcp>=1.9.0,<2"

COPY --from=tools /go/bin/ /usr/local/bin/
COPY --from=plan /nuclei-templates.txt /tmp/nuclei-templates.txt
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then export GIT_SSL_CAINFO=/run/secrets/extra_ca; fi \
    && read -r repo tag dir < /tmp/nuclei-templates.txt \
    && git clone --quiet --depth 1 --branch "${tag}" "${repo}" "${dir}" \
    && rm -rf "${dir}/.git" /tmp/nuclei-templates.txt

ENV PYTHONPATH=/opt \
    PYTHONUNBUFFERED=1 \
    BUGGY_SKIP_BOOT=1 \
    BUGGY_PIPELINE_DATA=/data/pipeline \
    BUGGY_CONTROL_ROOT=/control \
    HOME=/home/pipeline
COPY packages/buggy/buggy/__init__.py /opt/buggy/__init__.py
COPY packages/buggy/buggy/pipeline /opt/buggy/pipeline
COPY packages/buggy-core/buggy_core /opt/buggy_core

# Fails the build if any pinned tool is missing or reports another version.
RUN python -m buggy.pipeline.versions --write-manifest /opt/buggy/pipeline-tools.json

RUN useradd --uid 10001 --create-home --home-dir /home/pipeline pipeline \
    && mkdir -p /data/pipeline && chown -R pipeline:pipeline /data/pipeline
USER pipeline
WORKDIR /home/pipeline

ENTRYPOINT ["python", "-m", "buggy.pipeline"]
CMD ["worker"]
