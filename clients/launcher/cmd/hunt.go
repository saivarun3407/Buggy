package cmd

import (
	"strconv"
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/spf13/cobra"
)

var (
	huntScope          []string
	huntExclude        []string
	huntIncludeSubs    bool
	huntScopeFile      string
	huntInstruction    string
	huntMode           string
	huntPlanOnly       bool
	huntNonInteractive bool
	huntYes            bool
	huntNoAgent        bool
	huntLab            bool
	huntInternal       bool
	huntAllowSandbox   bool
	huntPortScan       bool
	huntRPS            int
)

var huntCmd = &cobra.Command{
	Use:   "hunt TARGET [TARGET...]",
	Short: "Start a hunt against a target in one command",
	Long: "Give it a URL you are authorized to test. Buggy brings the stack up " +
		"(running the setup wizard first if needed), enforces a scope of exactly " +
		"that host, maps it with the deterministic recon pipeline, writes a recon " +
		"report, then lets the agents pick what to test. State-changing requests " +
		"wait for your approval. Widen the scope explicitly with --scope or " +
		"--include-subdomains.\n\n" +
		"  buggy hunt example.com\n" +
		"  buggy hunt api.example.com app.example.com --include-subdomains\n" +
		"  buggy hunt https://example.com --scope '*.example.com' --instruction 'focus auth'",
	Args: cobra.MinimumNArgs(1),
	RunE: runHunt,
}

func init() {
	huntCmd.Flags().StringArrayVar(&huntScope, "scope", nil, "Extra in-scope pattern: host, *.domain, IP, CIDR (repeatable)")
	huntCmd.Flags().StringArrayVar(&huntExclude, "exclude", nil, "Out-of-scope pattern (repeatable)")
	huntCmd.Flags().BoolVar(&huntIncludeSubs, "include-subdomains", false, "Also put every subdomain of each target host in scope")
	huntCmd.Flags().StringVar(&huntScopeFile, "scope-file", "", "Scope file (JSON or text) to merge into scope")
	huntCmd.Flags().StringVar(&huntInstruction, "instruction", "", "Free-form focus/auth notes for the orchestrator")
	huntCmd.Flags().StringVar(&huntMode, "mode", "enforce", "RoE enforcement mode: audit|warn|enforce")
	huntCmd.Flags().BoolVar(&huntPlanOnly, "plan-only", false, "Write the plan bundle and exit without dispatching")
	huntCmd.Flags().BoolVarP(&huntNonInteractive, "non-interactive", "n", false, "Emit JSONL events instead of progress lines")
	huntCmd.Flags().BoolVarP(&huntYes, "yes", "y", false, "I am authorized to test these targets; do not prompt")
	huntCmd.Flags().BoolVar(&huntNoAgent, "no-agent", false, "Recon and report only; no LLM")
	huntCmd.Flags().BoolVar(&huntLab, "lab", false, "Training target you own: no approval holds, private addresses allowed")
	huntCmd.Flags().BoolVar(&huntInternal, "internal", false, "Target is on a private network")
	huntCmd.Flags().BoolVar(&huntAllowSandbox, "allow-sandbox-network", false, "Let the agent shell reach in-scope targets directly (not held for approval)")
	huntCmd.Flags().BoolVar(&huntPortScan, "port-scan", false, "Scan the top 100 ports")
	huntCmd.Flags().IntVar(&huntRPS, "rps", 0, "Requests per second (default 5)")
	rootCmd.AddCommand(huntCmd)
}

func runHunt(cmd *cobra.Command, args []string) error {
	_, env, err := prepareStack(cmd)
	if err != nil {
		return err
	}

	// Non-interactive hunt: leave BUGGY_ENGAGEMENT_WORKSPACE unset so the
	// whole workspace tree mounts at /workspace. buggy-cli hunt writes
	// plan/roe.json under <root>/<slug> and tells the agent workspace_path is
	// /workspace/<slug>; keeping the root at /workspace makes those resolve
	// identically for the langgraph agent and the sandbox.
	if err := startServices(env); err != nil {
		return err
	}

	cliArgs := []string{"buggy-cli", "hunt"}
	cliArgs = append(cliArgs, args...)
	for _, s := range huntScope {
		cliArgs = append(cliArgs, "--scope", s)
	}
	for _, e := range huntExclude {
		cliArgs = append(cliArgs, "--exclude", e)
	}
	if huntIncludeSubs {
		cliArgs = append(cliArgs, "--include-subdomains")
	}
	if huntScopeFile != "" {
		cliArgs = append(cliArgs, "--scope-file", huntScopeFile)
	}
	if huntInstruction != "" {
		cliArgs = append(cliArgs, "--instruction", huntInstruction)
	}
	cliArgs = append(cliArgs, "--mode", huntMode)
	if huntPlanOnly {
		cliArgs = append(cliArgs, "--plan-only")
	}
	if huntNonInteractive {
		cliArgs = append(cliArgs, "--non-interactive")
	}
	for flag, on := range map[string]bool{
		"--yes":                   huntYes,
		"--no-agent":              huntNoAgent,
		"--lab":                   huntLab,
		"--internal":              huntInternal,
		"--allow-sandbox-network": huntAllowSandbox,
		"--port-scan":             huntPortScan,
	} {
		if on {
			cliArgs = append(cliArgs, flag)
		}
	}
	if huntRPS > 0 {
		cliArgs = append(cliArgs, "--rps", strconv.Itoa(huntRPS))
	}

	ui.Info("Starting hunt against: " + strings.Join(args, ", "))

	// Run as a one-off `operator` container. It carries the python buggy
	// package (same image as langgraph) and is the only container with the
	// control root mounted read-write: `buggy-cli hunt` writes the enforced
	// scope there, which the langgraph and sandbox services can only read.
	c := compose.New()
	if err := c.RunInteractive([]string{compose.Profiles.Operator}, "operator", nil, cliArgs...); err != nil {
		return err
	}

	ui.DimText("Hunt finished. Recon report: ~/.buggy/control/<engagement>/recon-report.md. " +
		"Findings: ~/.buggy/workspace/<engagement>/findings/. " +
		"Run 'buggy' to open the UI, or 'buggy stop' to shut the stack down.")
	return nil
}
