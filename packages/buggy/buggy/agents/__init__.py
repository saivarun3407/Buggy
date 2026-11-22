# Standard bundle — buggy main agent + 16 official subagents + soundwave.
# Plugins bundle — vulnresearch main agent + its 5 subagents (community-plugin
# shape demonstrated from inside OSS). See buggy/agents/plugins/__init__.py.
from buggy.agents.plugins.detector import create_detector_agent
from buggy.agents.plugins.exploiter import create_exploiter_agent
from buggy.agents.plugins.patcher import create_patcher_agent
from buggy.agents.plugins.scanner import create_scanner_agent
from buggy.agents.plugins.verifier import create_verifier_agent
from buggy.agents.plugins.vulnresearch import create_vulnresearch_agent
from buggy.agents.standard.analyst import create_analyst_agent
from buggy.agents.standard.asvs_assessor import create_asvs_assessor_agent
from buggy.agents.standard.blue_cell import create_blue_cell_agent
from buggy.agents.standard.buggy import create_buggy_agent
from buggy.agents.standard.contract_auditor import create_contract_auditor_agent
from buggy.agents.standard.exploit import create_exploit_agent
from buggy.agents.standard.recon import create_recon_agent
from buggy.agents.standard.soundwave import create_soundwave_agent

__all__ = [
    "create_recon_agent",
    "create_soundwave_agent",
    "create_analyst_agent",
    "create_asvs_assessor_agent",
    "create_exploit_agent",
    "create_buggy_agent",
    "create_contract_auditor_agent",
    "create_blue_cell_agent",
    # WAVE-3 specialists — lit up over the pre-existing skill trees.
    # Vulnresearch pipeline (five-stage modular)
    "create_scanner_agent",
    "create_detector_agent",
    "create_verifier_agent",
    "create_patcher_agent",
    "create_exploiter_agent",
    "create_vulnresearch_agent",
]
