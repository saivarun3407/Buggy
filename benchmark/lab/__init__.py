"""Capability baseline against local, intentionally vulnerable applications.

Every target here is a container on the lab network of the local Docker
host. Nothing in this package can be pointed at an external host: the lab's
RoE lists only the lab service names, and the stack's egress guard and the
pipeline's scope filter enforce it.
"""
