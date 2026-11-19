"""Deterministic recon pipeline — no LLM anywhere in this package.

The design rule: anything a tool can do deterministically never goes to an
agent. Scanners run here as plain subprocesses, their output is parsed by
plain code into one normalised schema, and the result is written to the recon
store. Agents get read-only query tools over that store (``mcp_server``) and
one write: asking for a re-run of a named, in-scope asset.

Stage order (``stages.STAGES``):

1. subdomain enumeration   subfinder, amass (passive), certificate transparency
2. DNS resolution          dnsx: A / AAAA / CNAME / MX / TXT / NS
3. live hosts and ports    naabu, httpx
4. fingerprints            tech, TLS and response headers (from the httpx probe)
5. URLs and endpoints      katana, gau, waybackurls, JS file parsing
6. API specifications      OpenAPI / Swagger, GraphQL introspection
7. known issues            nuclei (vetted template set), secret scanning

Every stage filters its inputs and its outputs against the engagement's
enforced scope. Out-of-scope assets are dropped and logged, never scanned.

Nothing in this package imports langchain, langgraph or an LLM client; a
unit test enforces that.
"""

PIPELINE_SCHEMA_VERSION = 1
