package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/saivarun3407/buggy/clients/launcher/internal/updater"
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
	huntNoProbes       bool
	huntAgent          string
	huntCreateAccounts bool
	huntAccountEmail   string
	huntProbeBudget    string
	huntLab            bool
	huntInternal       bool
	huntAllowSandbox   bool
	huntPortScan       bool
	huntRPS            int
	huntLite           bool
	huntEngagement     string
	huntResume         string
	huntFailOn         string
	huntFailOnIssues   bool
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
		"  buggy hunt https://example.com --scope '*.example.com' --instruction 'focus auth'\n" +
		"  buggy hunt example.com --lite    (recon and report only, no model key)",
	Args: func(cmd *cobra.Command, args []string) error {
		// --resume takes its targets from the stored engagement.
		if huntResume != "" {
			return nil
		}
		return cobra.MinimumNArgs(1)(cmd, args)
	},
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
	huntCmd.Flags().StringVar(&huntAgent, "agent", agentAuto, "Who runs the agent stage: auto (Buggy's agents when a model is configured, else Claude Code on this machine if installed), builtin, or claude-code")
	huntCmd.Flags().BoolVar(&huntCreateAccounts, "create-accounts", false, "Allow Buggy to register up to two test accounts on the target (your approval for those requests); needs --account-email unless --lab")
	huntCmd.Flags().StringVar(&huntAccountEmail, "account-email", "", "Email pattern you control for created accounts, with {tag}, e.g. you+{tag}@your-domain.example")
	huntCmd.Flags().BoolVar(&huntNoProbes, "no-probes", false, "Do not run the automatic read-only probe sweep after recon")
	huntCmd.Flags().StringVar(&huntProbeBudget, "probe-budget", "", "Most probe runs the automatic sweep makes (default 40; 0 turns it off)")
	huntCmd.Flags().BoolVar(&huntLab, "lab", false, "Training target you own: no approval holds, private addresses allowed")
	huntCmd.Flags().BoolVar(&huntInternal, "internal", false, "Target is on a private network")
	huntCmd.Flags().BoolVar(&huntAllowSandbox, "allow-sandbox-network", false, "Let the agent shell reach in-scope targets directly (not held for approval)")
	huntCmd.Flags().BoolVar(&huntPortScan, "port-scan", false, "Scan the top 100 ports")
	huntCmd.Flags().IntVar(&huntRPS, "rps", 0, "Requests per second (default 5)")
	huntCmd.Flags().BoolVar(&huntLite, "lite", false, liteFlagHelp)
	huntCmd.Flags().StringVar(&huntEngagement, "engagement-name", "", "Name of the engagement (default: derived from the target)")
	huntCmd.Flags().StringVar(&huntResume, "resume", "", "Continue the named engagement with its stored targets and options (no TARGET needed)")
	huntCmd.Flags().StringVar(&huntFailOn, "fail-on", "", "Exit 10 when an exploit-verified finding is at or above: critical|high|medium|low|info")
	huntCmd.Flags().BoolVar(&huntFailOnIssues, "fail-on-issues", false, "With --fail-on: also count known issues from the recon report")
	rootCmd.AddCommand(huntCmd)
}

// liteFlagHelp is the help text of --lite. It states the one limit of the
// lite stack a user can run into.
const liteFlagHelp = "Recon and report only, on the lite stack (docker-compose.lite.yml): " +
	"no model key needed, implies --no-agent. The lite stack uses the same " +
	"service, container, volume and network names as the full stack, so the " +
	"two cannot run side by side from one Buggy home"

// liteServices are the long-running services of the lite stack. The operator
// is a one-off container and is not started with them.
var liteServices = []string{"pipeline", "pipeline-mcp"}

// huntFlags is the state of the hunt flags for one invocation.
type huntFlags struct {
	scope          []string
	exclude        []string
	includeSubs    bool
	scopeFile      string
	instruction    string
	mode           string
	planOnly       bool
	nonInteractive bool
	yes            bool
	noAgent        bool
	noProbes       bool
	agent          string // auto | builtin | claude-code
	createAccounts bool
	accountEmail   string
	claudeCode     bool   // decided once: Claude Code runs the agent stage
	probeBudget    string // a number; empty: not set
	lab            bool
	internal       bool
	allowSandbox   bool
	portScan       bool
	rps            int
	lite           bool
	engagement     string
	resume         string
	failOn         string
	failOnIssues   bool
}

func currentHuntFlags() huntFlags {
	return huntFlags{
		scope:          huntScope,
		exclude:        huntExclude,
		includeSubs:    huntIncludeSubs,
		scopeFile:      huntScopeFile,
		instruction:    huntInstruction,
		mode:           huntMode,
		planOnly:       huntPlanOnly,
		nonInteractive: huntNonInteractive,
		yes:            huntYes,
		noAgent:        huntNoAgent,
		noProbes:       huntNoProbes,
		agent:          huntAgent,
		createAccounts: huntCreateAccounts,
		accountEmail:   huntAccountEmail,
		probeBudget:    huntProbeBudget,
		lab:            huntLab,
		internal:       huntInternal,
		allowSandbox:   huntAllowSandbox,
		portScan:       huntPortScan,
		rps:            huntRPS,
		lite:           huntLite,
		engagement:     huntEngagement,
		resume:         huntResume,
		failOn:         huntFailOn,
		failOnIssues:   huntFailOnIssues,
	}
}

// skipsModelAuth reports whether this hunt never calls a model, and so must
// not be refused for lacking a model provider.
func (f huntFlags) skipsModelAuth() bool {
	return f.lite || f.claudeCode
}

// huntCompose returns the stack a hunt runs on: the lite file of the Buggy
// home with --lite, the full stack otherwise.
func huntCompose(lite bool) *compose.Compose {
	if lite {
		return compose.NewWithFile(compose.LiteFile)
	}
	return compose.New()
}

// huntOperatorCommand builds the command the one-off operator container runs.
//
// The full stack's operator image has the `buggy-cli` script. The lite
// stack's operator is the slim pipeline image, which does not: there the same
// command runs as a module, and --no-agent is always passed because the lite
// stack has no agent runtime to hand over to.
func huntOperatorCommand(targets []string, f huntFlags) []string {
	cliArgs := []string{"buggy-cli", "hunt"}
	if f.lite {
		cliArgs = []string{"python", "-m", "buggy.cli", "hunt"}
	}
	cliArgs = append(cliArgs, targets...)
	for _, s := range f.scope {
		cliArgs = append(cliArgs, "--scope", s)
	}
	for _, e := range f.exclude {
		cliArgs = append(cliArgs, "--exclude", e)
	}
	if f.includeSubs {
		cliArgs = append(cliArgs, "--include-subdomains")
	}
	if f.scopeFile != "" {
		cliArgs = append(cliArgs, "--scope-file", f.scopeFile)
	}
	if f.instruction != "" {
		cliArgs = append(cliArgs, "--instruction", f.instruction)
	}
	cliArgs = append(cliArgs, "--mode", f.mode)
	if f.planOnly {
		cliArgs = append(cliArgs, "--plan-only")
	}
	if f.nonInteractive {
		cliArgs = append(cliArgs, "--non-interactive")
	}
	for _, toggle := range []struct {
		flag string
		on   bool
	}{
		{"--yes", f.yes},
		// With Claude Code as the agent, the operator's hunt stops before its own
		// agent stage; the launcher runs Claude Code afterwards.
		{"--no-agent", f.noAgent || f.lite || f.claudeCode},
		{"--no-probes", f.noProbes},
		{"--create-accounts", f.createAccounts},
		{"--lab", f.lab},
		{"--internal", f.internal},
		{"--allow-sandbox-network", f.allowSandbox},
		{"--port-scan", f.portScan},
	} {
		if toggle.on {
			cliArgs = append(cliArgs, toggle.flag)
		}
	}
	if f.rps > 0 {
		cliArgs = append(cliArgs, "--rps", strconv.Itoa(f.rps))
	}
	if f.accountEmail != "" {
		cliArgs = append(cliArgs, "--account-email", f.accountEmail)
	}
	if f.probeBudget != "" {
		cliArgs = append(cliArgs, "--probe-budget", f.probeBudget)
	}
	if f.engagement != "" {
		cliArgs = append(cliArgs, "--engagement-name", f.engagement)
	}
	if f.resume != "" {
		cliArgs = append(cliArgs, "--resume", f.resume)
	}
	if f.failOn != "" {
		cliArgs = append(cliArgs, "--fail-on", f.failOn)
	}
	if f.failOnIssues {
		cliArgs = append(cliArgs, "--fail-on-issues")
	}
	return cliArgs
}

// Exit codes of `buggy-cli hunt`, passed through so `buggy hunt` works as a
// CI gate: 0 complete and nothing at or above --fail-on, 10 complete with
// something at or above it, 3 incomplete, 2 usage or configuration.
const (
	huntExitGate       = 10
	huntExitIncomplete = 3
	huntExitUsage      = 2
)

// huntExit ends the process with the hunt's verdict. It is a variable so
// tests can observe the code.
var huntExit = os.Exit

// huntVerdict maps the operator container's result to the code `buggy hunt`
// exits with and a line saying what it means. ok is false when err is not an
// exit status of the hunt itself (the container could not be started).
func huntVerdict(err error) (code int, message string, ok bool) {
	var exit *exec.ExitError
	if err == nil || !errors.As(err, &exit) {
		return 0, "", false
	}
	switch exit.ExitCode() {
	case huntExitGate:
		return huntExitGate, "Hunt finished: something is at or above --fail-on (exit 10). See hunt-result.json.", true
	case huntExitIncomplete:
		return huntExitIncomplete, "Hunt is incomplete (exit 3): recon or the agent stage did not finish. Re-run with --resume to continue.", true
	case huntExitUsage:
		return huntExitUsage, "Hunt was not started (exit 2): see the message above.", true
	}
	return exit.ExitCode(), "", false
}

func runHunt(cmd *cobra.Command, args []string) error {
	flags := currentHuntFlags()
	claude, err := useClaudeCode(flags.agent, flags.lite, flags.noAgent, noModelSetup(), claudeAvailable())
	if err != nil {
		return err
	}
	flags.claudeCode = claude
	_, env, err := prepareStackFor(cmd, flags.skipsModelAuth())
	if err != nil {
		return err
	}

	if flags.lite {
		lite := huntCompose(true)
		if err := ensureComposeFiles(env, lite); err != nil {
			return err
		}
		if err := startLiteServices(env, lite, liteServices...); err != nil {
			return err
		}
	} else {
		// Non-interactive hunt: leave BUGGY_ENGAGEMENT_WORKSPACE unset so the
		// whole workspace tree mounts at /workspace. buggy-cli hunt writes
		// plan/roe.json under <root>/<slug> and tells the agent workspace_path is
		// /workspace/<slug>; keeping the root at /workspace makes those resolve
		// identically for the langgraph agent and the sandbox.
		if err := startServices(env); err != nil {
			return err
		}
	}

	cliArgs := huntOperatorCommand(args, flags)
	c := huntCompose(flags.lite)

	if flags.resume != "" {
		ui.Info("Resuming hunt: " + flags.resume)
	} else {
		ui.Info("Starting hunt against: " + strings.Join(args, ", "))
	}

	// Run as a one-off `operator` container. It carries the python buggy
	// package (same image as langgraph; the slim pipeline image in the lite
	// stack) and is the only container with the control root mounted
	// read-write: `buggy-cli hunt` writes the enforced scope there, which the
	// other services can only read.
	var operatorEnv map[string]string
	pointer := ""
	if flags.claudeCode {
		// The engagement name is derived inside the operator's hunt; it writes
		// it to this one-time file so the agent stage knows which one to run.
		if pointer, err = newHuntPointer(); err != nil {
			return err
		}
		operatorEnv = map[string]string{pointerEnvKey: pointer}
	}
	runErr := c.RunInteractive([]string{compose.Profiles.Operator}, "operator", operatorEnv, cliArgs...)
	if flags.claudeCode {
		slug := readHuntPointer(controlDir(env), pointer)
		code, _, known := huntVerdict(runErr)
		// Recon finished (exit 0, or 10 when the gate already trips): the agent
		// stage runs, and its finalize step gives the run's verdict.
		if slug != "" && (runErr == nil || (known && code == huntExitGate)) {
			runErr = claudeAgentStage(c, slug, flags.failOn, flags.failOnIssues)
		}
	}
	if runErr != nil {
		code, message, ok := huntVerdict(runErr)
		if !ok {
			return runErr
		}
		ui.Warning(message)
		huntExit(code)
		return nil
	}

	if flags.lite {
		ui.DimText("Hunt finished. Recon report: ~/.buggy/control/<engagement>/recon-report.md. " +
			"The lite stack is still running; stop it with: " + stopCommand(c))
		return nil
	}
	ui.DimText("Hunt finished. Recon report: ~/.buggy/control/<engagement>/recon-report.md. " +
		"Findings: ~/.buggy/workspace/<engagement>/findings/. " +
		"Run 'buggy' to open the UI, or 'buggy stop' to shut the stack down.")
	return nil
}

// stopCommand is the command line that takes the stack c down, for hints.
func stopCommand(c *compose.Compose) string {
	bin := c.Runtime.Bin
	if bin == "" {
		bin = "docker"
	}
	return bin + " " + strings.Join(c.DownArgs(), " ")
}

// syncConfigFn is indirected so tests can see a download being requested
// without reaching GitHub.
var syncConfigFn = updater.SyncConfigFiles

// ensureComposeFiles makes sure every compose file of c is in the Buggy home.
//
// prepareStack downloads the release's config files only when the full
// compose file is absent. An install that predates the lite and demo files
// has that file but not these, so they are fetched here the same way.
func ensureComposeFiles(env map[string]string, c *compose.Compose) error {
	if len(c.MissingFiles()) == 0 {
		return nil
	}
	ref := "v" + version
	if version == "dev" || version == "" {
		ref = config.Get(env, "BUGGY_BRANCH", "main")
	}
	ui.Info("Downloading configuration files...")
	if err := syncConfigFn(ref, nil); err != nil {
		return fmt.Errorf("sync config: %w", err)
	}
	if missing := c.MissingFiles(); len(missing) > 0 {
		return fmt.Errorf("missing after sync (%s): %s", ref, strings.Join(missing, ", "))
	}
	return nil
}

// startLiteServices brings the named services of a lite-based stack up and
// blocks until their healthchecks pass.
//
// It is startServices without everything the lite stack does not have: no
// opscontrol daemon, no database or gateway credentials to refuse, no
// langgraph to wait for. The lite file has no env_file; the one secret it
// needs, BUGGY_STACK_MCP_TOKEN, is interpolated from .env, where it is
// generated when missing.
func startLiteServices(env map[string]string, c *compose.Compose, services ...string) error {
	generated, err := config.EnsureScopeSecrets(config.EnvPath(), env)
	if err != nil {
		return fmt.Errorf("generate scope-enforcement secrets: %w", err)
	}
	if len(generated) > 0 {
		ui.Info("Generated " + strings.Join(generated, ", ") + " in " + config.EnvPath())
	}

	ui.Info("Starting Buggy services (lite: " + strings.Join(services, ", ") + ")...")
	if err := c.UpServices(services...); err != nil {
		return fmt.Errorf("start services: %w", err)
	}
	return nil
}
