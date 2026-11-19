"""Capture gateway — trusted HTTP evidence for findings.

A finding is only as good as its proof. If the proof is a request the agent
says it sent, from a sandbox the agent controls, it is an assertion. This
package is where requests that count as evidence are sent from:

* The gateway runs in its own container. The agent supplies a method, URL,
  headers and body; the gateway sends the request and keeps the exchange.
* Every URL is checked against the engagement's enforced scope before
  anything is sent. Redirects are returned, not followed.
* Program rate limits apply here, per engagement.
* A request that can change state (anything but GET / HEAD / OPTIONS) is
  held for human approval when the engagement requires it.
* Captures live in a store the sandbox cannot reach, with a hash-chained
  ledger line per exchange. A capture can be replayed by the gateway itself,
  which is what "reproducible" means for a PoC.

``probes`` are deterministic checks built on the gateway (IDOR comparison,
JWT forgery, SSRF canary, numeric-boundary, mass assignment, GraphQL). The
agent decides where to point one; the mechanical work and the evidence are
plain code.

No model or agent library is imported here.
"""
