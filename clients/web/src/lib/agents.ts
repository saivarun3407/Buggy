/* ── Agent Display Config & Dynamic Registry ──────────────────────────
 *
 * "Which agents exist" is determined by the backend (LangGraph Platform).
 * "How to display them" is determined by this frontend config.
 *
 * New agents added to langgraph.json appear automatically with default styling.
 * To customize, add an entry to AGENT_DISPLAY_CONFIG.
 */

// ── Types ──

export interface AgentDisplayMeta {
  name?: string;
  description?: string;
  role: string;
  color: string;
  imagePath?: string;
}

export interface AgentConfig {
  id: string;
  name: string;
  description: string;
  role: string;
  color: string;
  imagePath?: string;
  mascotEmoji?: string;
  /** Agent origin — reserved for future marketplace/plugin use */
  source?: "builtin" | "marketplace" | "custom";
  /** Searchable tags — reserved for future filtering */
  tags?: string[];
  /** Advertised capabilities — reserved for future UI */
  capabilities?: string[];
}

export interface KillChainPhase {
  role: string;
  label: string;
}

export interface KillChainGroup extends KillChainPhase {
  agents: AgentConfig[];
}

// ── Kill chain phase ordering ──

export const KILL_CHAIN_PHASES: KillChainPhase[] = [
  { role: "Orchestrator", label: "Orchestrator" },
  { role: "Planning", label: "Planning" },
  { role: "Reconnaissance", label: "Reconnaissance" },
  { role: "Exploitation", label: "Exploitation" },
  { role: "Post-Exploitation", label: "Post-Exploitation" },
  { role: "Analysis", label: "Analysis" },
  { role: "Domain Specialist", label: "Domain Specialists" },
  { role: "Vulnerability Research", label: "Vulnerability Research" },
];

// ── Display config (frontend-only visual metadata) ──

export const AGENT_DISPLAY_CONFIG: Record<string, AgentDisplayMeta> = {
  buggy: {
    name: "Buggy",
    description: "Main orchestrator — commands the full kill chain",
    role: "Orchestrator",
    color: "#ef4444",
    imagePath: "/agents/buggy.png",
  },
  soundwave: {
    name: "Soundwave",
    description: "Socratic interview — generates RoE, CONOPS, OPPLAN",
    role: "Planning",
    color: "#8b5cf6",
  },
  recon: {
    name: "Recon",
    description: "Reconnaissance — port scanning, service enumeration",
    role: "Reconnaissance",
    color: "#3b82f6",
  },
  exploit: {
    name: "Exploit",
    description: "Initial access — exploit development and execution",
    role: "Exploitation",
    color: "#f59e0b",
  },
  analyst: {
    name: "Analyst",
    description: "Deep vulnerability analysis — SSRF, SQLi, XSS chains",
    role: "Analysis",
    color: "#f97316",
  },
};

// ── Default display for unknown/new agents ──

const DEFAULT_DISPLAY: AgentDisplayMeta = {
  role: "Uncategorized",
  color: "#6b7280",
};

// ── Registry helpers ──

/** Merge a backend agent ID with frontend display config → full AgentConfig */
export function buildAgentConfig(
  id: string,
  backendMeta?: { description?: string },
): AgentConfig {
  const display = AGENT_DISPLAY_CONFIG[id] ?? DEFAULT_DISPLAY;
  return {
    id,
    name:
      display.name ||
      id
        .replace(/_/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase()),
    description: backendMeta?.description ?? display.description ?? "",
    role: display.role,
    color: display.color,
    imagePath: display.imagePath,
    source: "builtin",
  };
}

/** Group agents by kill chain phase, with unknown roles in "Uncategorized" */
export function groupByKillChain(agents: AgentConfig[]): KillChainGroup[] {
  const knownRoles = new Set(KILL_CHAIN_PHASES.map((p) => p.role));

  const groups: KillChainGroup[] = KILL_CHAIN_PHASES.map((phase) => ({
    ...phase,
    agents: agents.filter((a) => a.role === phase.role),
  }));

  const uncategorized = agents.filter((a) => !knownRoles.has(a.role));
  if (uncategorized.length > 0) {
    groups.push({
      role: "Uncategorized",
      label: "Uncategorized",
      agents: uncategorized,
    });
  }

  return groups.filter((g) => g.agents.length > 0);
}

// ── Static fallback (used when LangGraph server is unreachable) ──

export const AGENTS: AgentConfig[] = Object.keys(AGENT_DISPLAY_CONFIG).map(
  (id) => buildAgentConfig(id),
);

// ── Legacy helpers (backwards-compatible) ──

export function getAgent(id: string): AgentConfig | undefined {
  return AGENTS.find((a) => a.id === id);
}

export function getAgentsByRole(role: string): AgentConfig[] {
  return AGENTS.filter((a) => a.role === role);
}
