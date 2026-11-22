"""Standard bundle — OSS-shipped agents.

Contains the official ``buggy`` main agent and its subagents
(recon, exploit, analyst, contract_auditor), plus the ``soundwave`` standalone planning
agent. Each subagent module exposes a ``SUBAGENT_SPEC`` declaring
``bundle="standard"`` and ``parent_agents=("buggy",)`` so the
plugin loader attaches them when the main agent is constructed.
"""
