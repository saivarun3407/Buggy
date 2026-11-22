/**
 * Display labels for agent names emitted by the backend.
 *
 * Backend emits snake_case names (e.g. "api_security", "authn_session").
 * Frontend converts via AGENT_LABELS for nice display.
 *
 * Unknown agents fall back to humanized (snake_case → Title Case).
 */

export const AGENT_LABELS: Record<string, string> = {
  // Orchestrator
  buggy: "Buggy",

  // Document generation
  soundwave: "Soundwave",

  // Kill chain
  recon: "Recon",
  exploit: "Exploit",

  // Specialist agents
  analyst: "Analyst",
};

/** Convert a backend agent name to its display label. */
export function labelForAgent(name: string | null | undefined): string {
  if (!name) return "idle";
  if (AGENT_LABELS[name]) return AGENT_LABELS[name];
  // Fallback: snake_case → Title Case
  return name
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
