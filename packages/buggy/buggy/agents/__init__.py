# Standard bundle — buggy main agent, its subagents, and soundwave.
from buggy.agents.standard.analyst import create_analyst_agent
from buggy.agents.standard.buggy import create_buggy_agent
from buggy.agents.standard.exploit import create_exploit_agent
from buggy.agents.standard.recon import create_recon_agent
from buggy.agents.standard.soundwave import create_soundwave_agent

__all__ = [
    "create_recon_agent",
    "create_soundwave_agent",
    "create_analyst_agent",
    "create_exploit_agent",
    "create_buggy_agent",
    # WAVE-3 specialists — lit up over the pre-existing skill trees.
]
