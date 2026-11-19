# Slim stand-in for the Kali sandbox image, used by the scope-enforcement
# end-to-end test (packages/buggy/tests/e2e/test_scope_enforcement_e2e.py).
#
# It runs the SAME entrypoint and the SAME sandbox daemon code as
# containers/sandbox.Dockerfile, copied to the same paths, so the route
# hand-off, capability drop and token check under test are the shipped ones.
# What it leaves out is the multi-gigabyte offensive toolset, which the
# boundary test does not need. nftables is installed on purpose: the test
# proves the agent cannot use it.
#
# Optional build secret ``extra_ca``: a PEM bundle to trust during the build
# (corporate / CI TLS-inspecting proxies). Not kept in the image config.
#
# ``PYTHON_IMAGE`` lets a build pull the base from a registry mirror
# (e.g. mirror.gcr.io/library/python:3.13-slim-bookworm) when Docker Hub
# rate-limits anonymous pulls.
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
FROM ${PYTHON_IMAGE}

RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then \
        printf 'Acquire::https::CaInfo "/run/secrets/extra_ca";\n' > /etc/apt/apt.conf.d/99extra-ca; \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        bash curl tmux iproute2 libcap2-bin nftables dnsutils iputils-ping procps && \
    rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99extra-ca

RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi && \
    pip install --no-cache-dir \
        "fastapi>=0.115.0" "uvicorn>=0.30.0" "deepagents>=0.5.0" "pydantic>=2.0.0"

COPY packages/buggy/buggy/__init__.py /opt/buggy/__init__.py
COPY packages/buggy/buggy/sandbox_kernel /opt/buggy/sandbox_kernel
COPY packages/buggy/buggy/sandbox_server /opt/buggy/sandbox_server
ENV PYTHONPATH=/opt \
    PYTHONUNBUFFERED=1 \
    BUGGY_SKIP_BOOT=1

WORKDIR /workspace
COPY containers/sandbox-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
