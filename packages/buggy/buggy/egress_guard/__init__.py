"""Egress guard — the sandbox's network boundary, in its own container.

The sandbox container runs the agent's commands as root. Any firewall loaded
inside that container can be flushed by the agent, so scope enforcement that
lives there is advisory. This package is the authoritative boundary instead:

* The sandbox sits on an ``internal`` Docker network with no route out. Its
  default route and DNS point at the guard.
* The guard forwards a packet only when the destination is allowed by the
  engagement's policy, and answers DNS only for names the policy allows.
* The rules live in the guard's network namespace. The sandbox has no
  ``CAP_NET_ADMIN`` once its entrypoint has finished, no route to the guard's
  control API, and does not hold the control token.
* Until a policy is pushed the guard forwards nothing (fail closed).
* Every dropped destination and every refused DNS name is written to a
  hash-chained ledger outside the sandbox.

The image ships only this package and the standard library.
"""
