# Offsec Harness Product-Fit Matrix

> Snapshot: 2026-11-17. Inventory source: [Offsec Harness Index](https://offsecharnesses.ai/). This is an exhaustive catalog matrix, not a performance ranking. “Best fit” summarizes the project’s stated purpose; it is not an independently verified efficacy claim.

## Buggy (review target)

| Tool | Product form | Best fit | Coverage | Evidence posture | Source |
|---|---|---|---|---|---|
| **Buggy** | Governed red-team platform | Supervised, engagement-scoped red-team operations where RoE, isolated execution, interactive tooling, knowledge-graph state, candidate/proof/corroboration gates, and multi-format reporting matter more than a minimal app-scanning workflow. | Recon, scanning, discovery, exploitation, exploit development, post-exploitation, research | Code-reviewed locally; focused/unit/live-Neo4j gates passed. No fresh whole-stack scan or trustworthy post-fix benchmark yet. | [Local architecture](../../ARCHITECTURE.md) |

## Index Inventory

### Confirmed-use harness (14)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **ARTEX** | Multi-agent pentest platform; repo closed Oct 2026, forks live on | Recon, Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | Closed/no canonical repo |
| **Cairn** | Multi-agent pentest framework | Recon, Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/oritera/Cairn) |
| **CyberStrikeAI** | LLM orchestrator with a built-in C2 | Recon, Scanning, Discovery, Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/AIPentest/CyberStrikeAI) |
| **PentestGPT** | Autonomous pentest agent | Recon, Scanning, Discovery, Exploitation, Research | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/GreyDGL/PentestGPT) |
| **PentAGI** | Multi-agent pentest system | Scanning, Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/vxcontrol/pentagi) |
| **OpenClaw** | General-purpose agent | Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/openclaw/openclaw) |
| **Hermes Agent** | Open-source autonomous agent with memory and self-written skills | Recon, Scanning, Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/NousResearch/hermes-agent) |
| **oh-my-claudecode** | Add-on layer for Claude Code | Scanning | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/Yeachan-Heo/oh-my-claudecode) |
| **Strix** | Multi-agent pentest framework | Recon, Scanning, Discovery, Exploitation, Exploit dev, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/usestrix/strix) |
| **HexStrike AI** | MCP server wrapping 150+ offensive tools | Recon, Scanning, Exploit dev, Research | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/0x4m4/hexstrike-ai) |
| **DeepAudit** | Multi-agent source-code auditor | Recon, Scanning, Discovery, Exploit dev | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/lintsinghua/DeepAudit) |
| **AntiFox** | ARTEX derivative; Chinese-language agentic pentest platform | Exploitation, Post-exploit | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/AntiFox-AI/antifox) |
| **CyberStrike** | Open-source AI pentest agent; not CyberStrikeAI | Recon, Discovery, Exploitation | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/CyberStrikeus/CyberStrike) |
| **HalberdStrike** | Pentest harness based on PentestGPT | Recon, Discovery | Confirmed real-world offensive use; capability still varies by operator and version. | [Repo](https://github.com/kuaiyelink/HalberdStrike) |

### Red-team platform (6)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **T3MP3ST** | Autonomous red-teaming platform: a multi-agent offensive meta-harness | Recon, Scanning, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/elder-plinius/T3MP3ST) |
| **Decepticon** | Autonomous hacking agent for red teams | Recon, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/BitterSecurity/Decepticon) |
| **Z3r0** | AI red-team workbench with specialist agents, sandboxed tooling and replayable timelines | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/yv1ing/Z3r0) |
| **Halberd** | Multi-cloud attack emulation tool with a Claude-powered agent that helps discover and execute attack paths | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/vectra-ai-research/Halberd) |
| **Pojun** | Chinese multi-agent platform that takes a one-line goal through recon, exploitation and post-exploitation to a report | Recon, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/chu0119/Pojun) |
| **Ares** | LLM-coordinated platform whose red-team agents chain 64+ Active Directory attack tools; also has a blue-team mode | Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/dreadnode/ares) |

### Pentest agent (58)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **Shannon** | AI pentester for web apps and APIs. Reads the source, then attacks the running app to prove each finding | Recon, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/KeygraphHQ/shannon) |
| **METATRON** | Local-LLM pentest assistant that runs recon tools and has the model analyze the results | Recon, Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/sooryathejas/METATRON) |
| **VulnClaw** | Chinese-language pentest CLI agent that takes a target from recon through exploitation to a report | Recon, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Netw0rkNoob/VulnClaw) |
| **RedAmon** | Self-hosted pentest framework that maps the attack surface into a graph and works it autonomously | Recon, Scanning, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/samugit83/redamon) |
| **PentestAgent** | Agent framework for black-box testing: bug bounty, red team and pentest | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/GH05TCREW/pentestagent) |
| **Pentest-Swarm-AI** | Swarm of agents that runs recon, classification and exploitation | Recon, Scanning, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Armur-Ai/Pentest-Swarm-AI) |
| **Deep Eye** | Pentest tool that has LLMs generate payloads and scan targets for 50+ vulnerability types | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/zakirkun/deep-eye) |
| **sapper** | Multi-agent pentest orchestration harness that won a Tencent Cloud attack-defense challenge qualifier | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/N1nEmAn/sapper-v2) |
| **pentest-ai** | AI pentester that re-runs each exploit to prove the finding | Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/0xSteph/pentest-ai) |
| **NeuroSploit** | AI-powered penetration testing framework | Recon, Scanning, Discovery, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/JoasASantos/NeuroSploit) |
| **LuaN1aoAgent** | Fully autonomous pentest agent built on graph-based reasoning | Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/SanMuzZzZz/LuaN1aoAgent) |
| **PentesterFlow** | Terminal pentest agent with skills, a Burp bridge and coverage tracking that keeps the analyst in control | Recon, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/PentesterFlow/agent) |
| **Xalgorix** | Pentest agent that exploit-verifies every finding across a 22-phase run | Recon, Scanning, Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/xalgorix/xalgorix) |
| **Dark-Moon** | Autonomous pentesting with 50 specialist agents across web, API, cloud and Active Directory | Recon, Scanning, Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ASCIT31/Dark-Moon) |
| **Vigolium** | Vulnerability scanner with an agentic mode whose swarm picks modules and writes custom attack extensions | Scanning, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/vigolium/vigolium) |
| **PentestCode** | Multi-agent pentest system that keeps engagement state between runs | Recon, Scanning, Discovery, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/s0ld13rr/pentestcode) |
| **AIRecon** | Autonomous cybersecurity agent built on a self-hosted LLM through Ollama | Recon, Scanning, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/pikpikcu/airecon) |
| **Clearwing** | Autonomous scanner and vulnerability hunter that runs Kali tools and builds exploits with human approval | Recon, Scanning, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Lazarus-ai-OSS/clearwing) |
| **Cain** | AI pentest engineer for real authorized assessments, with 46 tools and a cloud penetration module | Recon, Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/cdxiaodong/cain-agent) |
| **numasec** | AI agent for cyber security work | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/FrancescoStabile/numasec) |
| **StrikeAgent** | Chinese AI pentest platform with red-team re-rating and re-verification of findings, tested in CTF settings | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash) |
| **Muteki** | Offensive security harness for automated penetration testing | Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/FishCodeTech/muteki) |
| **Cyber-AutoAgent** | AI agent for autonomous cyber operations | Recon, Scanning, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/westonbrown/Cyber-AutoAgent) |
| **Mitsu** | Pentest agent client that runs an authorized engagement from recon through post-exploitation with 165+ MCP tools | Recon, Discovery, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ARCANGEL0/Mitsu) |
| **AIDA** | Turns any LLM into an autonomous pentester inside a scope you set | Recon, Scanning, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Vasco0x4/AIDA) |
| **Zen-Ai-Pentest** | Multi-agent pentest framework with automated vulnerability scanning | Recon, Scanning, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/SHAdd0WTAka/Zen-Ai-Pentest) |
| **AdStrike** | Active Directory attack framework with an MCP server so the user's own LLM host drives 53 tools | Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/capture0x/AdStrike) |
| **Rogue** | LLM web vulnerability scanner agent that generates test payloads and verifies findings | Recon, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/faizann24/rogue) |
| **Pentest Harness** | Self-hosted AI agent harness for authorized pentests, bug bounty, security labs and CTFs | Not stated | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/S1N6H/pentest-harness) |
| **cyber-harness** | Single-binary agent for pentest, red team and bug bounty | Recon, Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/chainreactors/cyber-harness) |
| **RedCell** | Agents run a penetration test end to end inside a Kali container | Scanning, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/martian56/redcell) |
| **BugTraceAI** | Self-hosted web pentesting suite with agentic scanning | Recon, Scanning, Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/BugTraceAI/BugTraceAI) |
| **Vibe Pentest** | Chinese multi-agent black-box pentest tool that mimics a human expert, including business-logic flaws | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ok-helloworld/vibe-pentest) |
| **RedAI** | Terminal workbench that finds vulnerabilities with AI, then validates them live with PoC scripts | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/kpolley/redai) |
| **TARS** | Agents that automate pentesting | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/osgil-defense/TARS) |
| **deadend-cli** | Self-hosted agentic pentest tooling for black-box testing, on any LiteLLM model | Recon, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/straylabs-ai/deadend-cli) |
| **Lyrie** | Pentest CLI that fingerprints and scans targets with AI-assisted exploit validation; also red-teams LLM endpoints | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai) |
| **Apex** | Terminal pentest agent that runs blackbox and whitebox tests with agent swarms in a Kali container | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/pensarai/apex) |
| **vulnerator-ai** | OODA-loop pentest agent on Hermes, with Kali and Playwright tools over MCP | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/irraz/vulnerator-ai) |
| **SecGPT** | AutoGPT-style LLM tool for pentesting, vulnerability scanning and code audit, with CTF aims | Scanning, Discovery, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ZacharyZcR/SecGPT) |
| **BlacksmithAI** | Multi-agent pentest framework with separate recon, vulnerability, exploit and post-exploit agents | Recon, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/yohannesgk/blacksmith) |
| **Watchtower** | LangGraph pentest CLI where LLM agents orchestrate 28 security tools | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/fzn0x/watchtower) |
| **Zypheron** | Local-first security CLI with recon, scanning and AI-assisted operator workflows | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/KKingZero/Zypheron-CLI) |
| **agent-smith** | Pentest framework where skills teach the LLM a methodology and it invents the attacks itself | Recon, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/0x0pointer/agent-smith) |
| **cochise** | Autonomous assumed-breach penetration testing of Active Directory networks | Exploitation, Post-exploit, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/andreashappe/cochise) |
| **Incalmo** | Autonomous LLM-driven network pentest tool for multistage attacks, built for a research paper | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/cylabcyberautonomy/Incalmo) |
| **Executioner** | Local workspace where teams of AI agents run an assessment against your tools and scope | Recon, Scanning, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/dbx0/executioner) |
| **Phalanx** | Multi-agent pentest framework with recon, exploit and post-exploit agents and 58 built-in tools | Recon, Scanning, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/webxos/phalanx) |
| **PentestAgent (nbshenxm)** | Research LLM framework that automates intelligence gathering, vulnerability analysis and exploitation stages | Recon, Discovery, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/nbshenxm/pentest-agent) |
| **claude-pentest** | Claude Code plugin with 15 agents and Kali MCP integration for full pentest engagements | Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Stickman230/claude-pentest) |
| **PentestAssistant** | LLM web pentest detector using function calling and multiple agents to run nmap and sqlmap | Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/InfSecLabs/PentestAssistant) |
| **Moxy** | Intercepting-proxy DAST tool where an AI agent reasons about attack surface, edits traffic and drives a browser | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/matank001/Moxy) |
| **pentestkit** | Multi-agent pentest framework on the Claude Agent SDK where a skeptical verifier tries to exploit each candidate | Recon, Exploitation, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/lordx64/pentestkit) |
| **Zack AI Scanner** | Burp Suite extension that runs an LLM pipeline against one request and sends the real payloads | Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ZackSecurity/Zack-AI-Scanner) |
| **AutoPentester** | Tool for automated pentesting tasks | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/YasodGinige/AutoPentester) |
| **CyberSentry** | Autonomous AI agent for website penetration testing and vulnerability assessment | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/prutxvi/cybersentry) |
| **SQLMap Skynet** | AI-assisted SQLMap orchestration with a dashboard and an MCP tool server for agents | Scanning, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/drcrypterdotru/sqlmap-skynet) |
| **HEAVEN** | Autonomous pentest framework with an LLM plan-act loop, vuln-hypothesis agent and post-exploitation playbook | Recon, Discovery, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing) |

### Bug-bounty agent (5)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **Agentic-Bug-Hunter** | AI bug-bounty hunting toolkit | Recon, Scanning, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/awarexone/Agentic-Bug-Hunter) |
| **Cybermes** | Offensive security and bug-bounty agent framework built on Hermes Agent | Recon, Scanning, Discovery, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Zyrexnn/Cybermes) |
| **Ars0n Framework v2** | Bug bounty recon framework whose MCP server exposes data and scans to AI assistants | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/R-s0n/ars0n-framework-v2) |
| **Flounder** | Turns coding agents into a security auditor for bug bounty work, with local exploit construction | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/adshao/flounder) |
| **Hacker Bob** | Autonomous bug bounty hunter built on a local MCP runtime, with a public portfolio of reported CVEs | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/vmihalis/hacker-bob) |

### Code auditor (12)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **RAPTOR** | Claude Code set up as an offensive and defensive security research agent | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/gadievron/raptor) |
| **Vulnhuntr** | Zero-shot vulnerability discovery with LLMs: traces code paths to find remotely exploitable bugs | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/protectai/vulnhuntr) |
| **Open Kritt** | Self-hosted platform that orchestrates AI agents to find and validate vulnerabilities in code | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Kritt-ai/open-kritt) |
| **AutoCVE** | Chinese-language agent platform that audits source code for vulnerabilities and drafts CVE reports | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/larlarua/AutoCVE) |
| **VulnHunter (Capital One)** | Agentic source-code hunter that reasons like an adversary and drops findings it cannot prove exploitable | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/capitalone/VulnHunter) |
| **audit** | Eight-stage Claude agent pipeline that hunts vulnerabilities and compiles proof-of-concept code | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/evilsocket/audit) |
| **Mantishack** | AI vulnerability pipeline with recon, attacker-simulation validation and gated exploitation over a codebase | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/deonmenezes/mantishack) |
| **OpenHack** | Open-model agent scanner that hunts, validates and exploit-tests vulnerabilities in a codebase | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/openhackai/OpenHack) |
| **Plamen** | Claude Code and Codex agent swarm that audits smart contracts and node clients with PoC exploits | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/PlamenTSV/plamen) |
| **raptor-loop-hunt** | Claude Code skill that loops a multi-altitude vulnerability hunt over a codebase | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/dinosn/raptor-loop-hunt) |
| **AIxVuln** | Chinese LLM multi-agent system that audits code, then verifies vulnerabilities with PoCs in Docker sandboxes | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/m4xxxxx/AIxVuln) |
| **FuzzingBrain** | LLM system built on OSS-Fuzz that finds vulnerabilities, builds PoC inputs and patches; a DARPA AIxCC entry | Discovery, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain) |

### Recon agent (3)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **FofaMap** | Chinese tool that ties FOFA asset discovery, AI reflection and Nuclei validation into one workflow | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/asaotomo/FofaMap) |
| **DorkAgent** | LLM agent that automates Google dorking for bug hunting and pentesting | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/yee-yore/DorkAgent) |
| **ZeroTrace** | Personal AI-powered dorking tool that uncovers sensitive information for recon | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/sergio11/zero_trace_hacking_tool) |

### MCP server (13)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **Burp AI Agent** | Burp Suite extension that adds AI scanners and an MCP bridge for AI agents | Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/six2dez/burp-ai-agent) |
| **MCP-Kali-Server** | MCP setup that gives an AI agent a Kali Linux machine and its tools | Recon, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Wh0am123/MCP-Kali-Server) |
| **MetasploitMCP** | MCP server that lets an agent drive Metasploit | Scanning, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/GH05TCREW/MetasploitMCP) |
| **MCP for Security** | MCP servers for SQLMap, FFUF, Nmap, Masscan and other security tools, for AI pentest workflows | Recon, Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/cyproxio/mcp-for-security) |
| **Blitz Strike** | MCP security toolbelt that maps attack surface, traces source-to-sink paths and verifies findings live | Recon, Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/shinthink/blitzstrike) |
| **h1-brain** | MCP server linking an AI assistant to HackerOne bug bounty history, scopes and reports | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/PatrikFehrenbach/h1-brain) |
| **BurpMCP-Ultra** | MCP server giving AI agents 150 Burp Suite Professional tools for scanning, fuzzing and traffic analysis | Scanning, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Cy-S3c/BurpMCP-Ultra) |
| **Scan-Spring-GO** | Go scanner and exploiter for Spring components that exposes all its modules to AI clients over MCP | Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/sspsec/Scan-Spring-GO) |
| **AutoPentest AI** | MCP server where Scout, Analyzer, Exploiter and Reporter agents run web pentests against OWASP test cases | Recon, Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/bhavsec/autopentest-ai) |
| **Pentest MCP** | Scoped MCP server giving assessment agents nmap, Nuclei, Hashcat and other tools for authorized tests | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/DMontgomery40/pentest-mcp) |
| **bloodhound_mcp** | MCP server that lets an LLM query BloodHound attack paths across Active Directory and Entra ID | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/mwnickerson/bloodhound_mcp) |
| **gori** | Terminal intercepting proxy and pentest toolkit whose MCP server lets AI agents drive the same engagement | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/hahwul/gori) |
| **awsome-kali-MCPServers** | Collection of MCP servers that expose Kali Linux tools to AI clients | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ccq1/awsome_kali_MCPServers) |

### C2 with MCP (4)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **emp3r0r** | Linux-first post-exploitation C2 whose MCP server lets an AI harness operate it in natural language | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/jm33-m0/emp3r0r) |
| **LeoAI** | Chinese post-exploitation management platform with platform-level and per-node AI copilots | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/cha0upup/LeoAI) |
| **LazyOwn** | Multi-operator C2 that exposes 153 MCP tools to AI agents | Recon, Scanning, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/grisuno/LazyOwn) |
| **WolfShell** | ASPX WebShell and C2 manager with an MCP server and AI-assisted penetration | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/0x7556/wolfshell) |

### Skill pack (23)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **reverse-skill** | Skill router that sends AI coding agents to reverse-engineering, pentest and CTF toolchains | Exploit dev, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/zhaoxuya520/reverse-skill) |
| **Claude-Red** | Library of offensive security skills for the Claude skills system | Recon, Discovery, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/SnailSploit/Claude-Red) |
| **Claude-BugHunter** | Claude Code skill bundle for bug hunting and external red-team work | Recon, Discovery, Exploitation, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/elementalsouls/Claude-BugHunter) |
| **ctf-skills** | Agent skills for solving CTF challenges across web, pwn, crypto, reversing and forensics | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ljagiello/ctf-skills) |
| **Claude-OSINT** | Eight Claude skills that prime the model with offensive recon methodology: asset discovery and exposure checks | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/elementalsouls/Claude-OSINT) |
| **hack-skills** | Knowledge base of 102 hacking skills that AI agents load, covering web, AD, pwn and mobile | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/yaklang/hack-skills) |
| **pentest-ai-agents** | Offensive-security subagents for Claude Code | Recon, Scanning, Discovery, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/0xSteph/pentest-ai-agents) |
| **recon-skills** | Skill pack for agents covering external recon, web and API testing, validation and attack paths | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/uphiago/recon-skills) |
| **dsh-redteam-model** | Ten red-team working modes and runtime plugins for the DeepSeek harness; README in Chinese | Discovery, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/SeaOf0/dsh-redteam-model) |
| **IoTHackBot** | IoT security testing toolkit with Claude Code skills for vulnerability discovery | Recon, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/BrownFineSecurity/iothackbot) |
| **src-hunter-skill** | Chinese Claude Code skill for SRC and bug bounty hunting with attack playbooks and payloads | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/MyuriKanao/src-hunter-skill) |
| **communitytools** | Claude Code skills, agents and commands for pentesting and bug bounty | Recon, Scanning, Discovery, Exploitation, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/transilienceai/communitytools) |
| **Bug-Bounty-Agents** | Drop-in agent personas for bug bounty recon, web hunting, PoC validation and reporting | Recon, Discovery, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/matty69v/Bug-Bounty-Agents) |
| **offensive-claude** | Spec-driven offensive framework for Claude Code with 32 kill-chain skills | Recon, Discovery, Exploit dev, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/hypnguyen1209/offensive-claude) |
| **pentest-skills** | Chinese pentest skill set for Claude Code and Gemini CLI that turns natural language into tool runs | Recon | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/crazyMarky/pentest-skills) |
| **red-run** | Claude Code skills, MCP servers and agent teams for pentest phases from recon to privilege escalation | Recon, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/blacklanternsecurity/red-run) |
| **Claude-AD** | Active Directory pentest playbook for Claude Code as skills, agents and slash commands | Recon, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ADScanPro/Claude-AD) |
| **web3-bug-bounty-hunting-ai-skills** | Eighteen Claude Code skill files for smart contract bug bounty hunting | Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/awarexone/web3-bug-bounty-hunting-ai-skills) |
| **kali-pentest** | Kali Linux pentest skill for Claude Code, OpenClaw and Hermes Agent, with 200+ CLI tools | Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/x-glacier/kali-pentest) |
| **CkSKILLS** | Chinese skill library that turns researcher methodology into reusable agent skills for SRC bug hunting | Recon, Discovery, Post-exploit | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/zhaji2333/CkSKILLS) |
| **forefy/.context** | AI agent skills for security audits, pentests and bug bounty work, from recon to PoC generation | Recon, Exploitation, Exploit dev | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/forefy/.context) |
| **aimy-skill** | Chinese pentest skill for AI agents with a structured check interface and exploit-chain engine | Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/Prohao42/aimy-skill) |
| **open-sesame** | Claude Code pentest skills for web and network engagements, from attack-surface mapping to reports | Recon, Discovery | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/hassan-algo/open-sesame) |

### CTF agent (5)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **ctf-agent** | Multi-model swarm that solves CTF challenges autonomously; won first place at BSidesSF 2026 | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/verialabs/ctf-agent) |
| **CHYing-agent** | Agent from Tencent Cloud AI pentest hackathons, ninth in the first year; README in Chinese | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/yhy0/CHYing-agent) |
| **BoxPwnr** | Framework that benchmarks LLM agents solving HackTheBox, PortSwigger, CTF and other security labs | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/0ca/BoxPwnr) |
| **NYU CTF agents** | Baseline and D-CIPHER LLM agents that solve CTF challenges for the NYU CTF Bench | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/NYU-LLM-CTF/nyuctf_agents) |
| **Heimdall** | Self-hosted AI solver and toolkit for CTF and security labs; top 2 at two Chinese challenges | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/QiantangCredit/heimdall-agent) |

### Research framework (4)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **hackingBuddyGPT** | Research framework for building LLM hacking agents in 50 lines or less | Scanning, Exploitation, Post-exploit, Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ipa-lab/hackingBuddyGPT) |
| **HackSynth** | LLM agent and evaluation framework for autonomous penetration testing | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/aielte-research/HackSynth) |
| **VulnBot** | Multi-agent framework for autonomous penetration testing | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/KHenryAegis/VulnBot) |
| **MAPTA** | Multi-agent system for autonomous web application security assessment | Not stated | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/arthurgervais/mapta) |

### Assistant (5)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **Pentest Copilot** | Browser-based AI assistant for ethical hacking | Recon, Scanning, Exploitation | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/bugbasesecurity/pentest-copilot) |
| **Nebula** | Cybersecurity harness for AI-assisted engagements | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/berylliumsec/nebula) |
| **Haiou Workshop** | Chinese AI workbench for reverse engineering, authorized pentests and CTF using Codex and Claude Code | Research | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/haiou-666/Haiou-workshop) |
| **AI-OPS** | Penetration testing assistant built on open-source LLMs | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/antoninoLorenzo/AI-OPS) |
| **Hexestra** | AI-native pentest workbench where Claude Code or Codex works with browser, shells and traffic capture | Scanning | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/ABSllk/Hexestra) |

### General agent (2)

| Tool | Best fit / strongest stated use | Coverage | Evidence posture | Source |
|---|---|---|---|---|
| **Agent Zero** | General agent framework that writes and runs its own code and tools. Google saw threat actors experimenting with it ( GTIG ↗ ) | Not stated | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/agent0ai/agent-zero) |
| **codex-redteam-mode** | Opt-in red-team operation runtime for Codex that injects a jailbreak prompt into the system layer | Not stated | Project/index stated; no independent performance result established by this matrix. | [Repo](https://github.com/chAng-L19/codex-redteam-mode) |

## Interpretation Rules

- “Best fit” means the clearest product job described by the project, not that it beats every peer at that job.
- Stars, recency, and real-world abuse are adoption/activity signals, not quality measurements.
- Confirmed malicious use proves operational usability in some context; it does not prove safe defaults, precision, or suitability for defensive teams.
- Benchmark claims remain vendor-authored unless an independent evaluator manually validates findings and publishes methodology.
