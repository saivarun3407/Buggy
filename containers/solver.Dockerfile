# Web-blind solver container — runs devin sessions with external egress
# blocked so benchmark solves can only come from the target, never from
# looking up published solutions online.
#
# Built on the langgraph image (python + devin binary + credentials mounts).
# The entrypoint installs an OUTPUT allowlist before handing off:
#   allow: loopback, embedded DNS, the host gateway (challenge targets via
#          host.docker.internal), and the devin backend endpoints
#   drop:  everything else (the general internet)
#
# LANGGRAPH_IMAGE names the base. The default is the image a source build
# tags locally; the release workflow passes the just-published
# ghcr.io/<owner>/buggy-langgraph:<version>, so a release solver is built on
# that release's agent image and nothing else.
ARG LANGGRAPH_IMAGE=buggy-langgraph:stable
FROM ${LANGGRAPH_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY containers/solver-entrypoint.sh /usr/local/bin/solver-entrypoint.sh
RUN chmod +x /usr/local/bin/solver-entrypoint.sh

# API endpoints the devin CLI needs to reach its model backend.
# Challenge targets are reached through the host gateway, not these.
ENV SOLVER_ALLOWED_HOSTS="api.devin.ai server.codeium.com app.devin.ai web-backend.codeium.com"

ENTRYPOINT ["/usr/local/bin/solver-entrypoint.sh"]
CMD ["sleep", "infinity"]
