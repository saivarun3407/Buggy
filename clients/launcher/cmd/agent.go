package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/spf13/cobra"
)

// The agent stage can be run by an agent the operator already has instead of
// Buggy's own: Claude Code, signed in with the operator's own account, so no
// model key is stored in Buggy. Claude Code gets Buggy's agent tools for one
// engagement through the bridge (`python -m buggy.agent_bridge`), which runs
// in the stack's operator container. It gets no shell and, of its own
// built-in tools, only web search (none with --no-web); every request it
// sends to the target still passes the scope check, the approval hold, the
// rate limit and the audit ledger of the stack's servers. Pages it reads on
// the web come through the bridge's research_fetch, which refuses the target,
// internal addresses and URLs that carry the target's data.
const (
	agentAuto    = "auto"
	agentBuiltin = "builtin"
	agentClaude  = "claude-code"

	claudeBinary  = "claude"
	bridgeServer  = "buggy"
	agentRunner   = "claude-code"
	pointerEnvKey = "BUGGY_HUNT_POINTER"

	// webSearchTool is Claude Code's built-in web search, the only built-in
	// it gets. WebFetch is never enabled: it would fetch from this machine, a
	// direct path to the target; pages are read through research_fetch.
	webSearchTool = "WebSearch"
	// webEnvKey tells the bridge to leave research_fetch out (--no-web).
	webEnvKey = "BUGGY_AGENT_WEB"
)

// noWebFlagHelp is the help of --no-web on `buggy agent` and `buggy hunt`.
const noWebFlagHelp = "Claude Code agent stage: no web search and no research_fetch (no public-internet lookups)"

// claudePrompt is all the launcher says; the instructions come from the
// bridge's engagement_brief tool, built from the enforced scope.
const claudePrompt = "Call the engagement_brief tool of the buggy server, then carry out the " +
	"engagement it describes using only that server's tools (web search, when you have it, is " +
	"for public documentation only). Work until candidates_next has nothing left for you or " +
	"the tools tell you to stop, then give your final summary."

const claudeSystem = "You are running unattended as the testing agent of an authorized " +
	"security engagement. The buggy tool server enforces the scope and holds anything " +
	"state-changing for the operator; treat every refusal as final and never ask for approval " +
	"or credentials."

var engagementName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`)

// Seams for tests.
var (
	claudeLookPath = exec.LookPath
	runClaudeFn    = runClaude
	finalizeHuntFn = finalizeHunt
)

var (
	agentFailOn       string
	agentFailOnIssues bool
	agentNoWeb        bool
)

var agentCmd = &cobra.Command{
	Use:   "agent ENGAGEMENT",
	Short: "Run the agent stage of an engagement with Claude Code (no model key)",
	Long: "Runs the agent stage of an engagement that `buggy hunt` already mapped, using " +
		"Claude Code on this machine with your own Claude sign-in. No model key is stored " +
		"in Buggy. Claude Code only gets Buggy's tools for this one engagement, plus web " +
		"search for public documentation (--no-web turns it off); scope, approvals, rate " +
		"limits and the audit ledger stay enforced by the stack.",
	Args: cobra.ExactArgs(1),
	RunE: runAgent,
}

func init() {
	agentCmd.Flags().StringVar(&agentFailOn, "fail-on", "", "Exit 10 when an exploit-verified finding is at or above: critical|high|medium|low|info")
	agentCmd.Flags().BoolVar(&agentFailOnIssues, "fail-on-issues", false, "With --fail-on: also count known issues from the recon report")
	agentCmd.Flags().BoolVar(&agentNoWeb, "no-web", false, noWebFlagHelp)
	rootCmd.AddCommand(agentCmd)
}

func claudeAvailable() bool {
	_, err := claudeLookPath(claudeBinary)
	return err == nil
}

// noModelSetup reports whether this install has no model configured: it was
// never set up, or it was set up for recon only.
func noModelSetup() bool {
	return !config.EnvExists() || isReconOnlyEnv()
}

// useClaudeCode decides who runs the agent stage of a hunt. "auto" picks
// Claude Code exactly when Buggy has no model of its own and Claude Code is
// installed, so a hunt on a machine without a key still gets its agent stage.
func useClaudeCode(mode string, lite, noAgent, noModel, claude bool) (bool, error) {
	switch mode {
	case agentBuiltin:
		return false, nil
	case agentClaude:
		if lite {
			return false, errors.New("--agent claude-code needs the full stack: the lite stack has no evidence gateway (drop --lite)")
		}
		if noAgent {
			return false, errors.New("--agent claude-code and --no-agent contradict each other")
		}
		if !claude {
			return false, errors.New("--agent claude-code: the `claude` command is not on PATH; install Claude Code and sign in (`claude`), then retry")
		}
		return true, nil
	case agentAuto, "":
		return !lite && !noAgent && noModel && claude, nil
	}
	return false, fmt.Errorf("--agent must be auto, builtin or claude-code, not %q", mode)
}

// claudeMCPConfig is the MCP configuration handed to Claude Code: one server,
// started by running the bridge in a one-off operator container of this
// stack. The compose command and its environment are the launcher's own, so
// the bridge joins exactly the stack `buggy hunt` started. Without web access
// the bridge is told (-e BUGGY_AGENT_WEB=off) to leave research_fetch out.
func claudeMCPConfig(c *compose.Compose, slug string, web bool) ([]byte, error) {
	var bridgeEnv map[string]string
	if !web {
		bridgeEnv = map[string]string{webEnvKey: "off"}
	}
	args := c.RunCapturedArgs(
		[]string{compose.Profiles.Operator}, "operator", bridgeEnv,
		"python", "-m", "buggy.agent_bridge", "--engagement", slug,
	)
	env := map[string]string{}
	for _, pair := range c.Env() {
		if name, value, ok := strings.Cut(pair, "="); ok && bridgeEnvName(name) {
			env[name] = value
		}
	}
	bin := c.Runtime.Bin
	if bin == "" {
		bin = "docker"
	}
	return json.MarshalIndent(map[string]any{
		"mcpServers": map[string]any{
			bridgeServer: map[string]any{"command": bin, "args": args, "env": env},
		},
	}, "", "  ")
}

// bridgeEnvName reports whether a variable of the compose environment is
// written into the MCP configuration. That file is read by another program,
// so it carries only what selects the stack (its name, home, image tags and
// the container runtime's socket) and never anything that looks like a
// secret; the stack's own secrets reach compose through its env-file.
func bridgeEnvName(name string) bool {
	for _, word := range []string{"TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL"} {
		if strings.Contains(name, word) {
			return false
		}
	}
	return strings.HasPrefix(name, "BUGGY_") || strings.HasPrefix(name, "COMPOSE_") || name == "DOCKER_HOST"
}

// claudeArgs is the Claude Code command line. `--tools` names the built-in
// tools it has: web search alone, or none at all without web access (no
// shell, no file access and no WebFetch either way); --strict-mcp-config
// ignores any other MCP server configured on this machine; the only tools
// allowed are the bridge's and, with web access, the search.
func claudeArgs(configPath string, web bool) []string {
	builtins, allowed := "", "mcp__"+bridgeServer
	if web {
		builtins, allowed = webSearchTool, allowed+","+webSearchTool
	}
	return []string{
		"-p", claudePrompt,
		"--mcp-config", configPath,
		"--strict-mcp-config",
		"--tools", builtins,
		"--allowedTools", allowed,
		"--append-system-prompt", claudeSystem,
	}
}

func runClaude(c *compose.Compose, slug string, web bool) error {
	body, err := claudeMCPConfig(c, slug, web)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "buggy-agent-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	cmd := exec.Command(claudeBinary, claudeArgs(path, web)...)
	cmd.Dir = dir // an empty folder: no project settings or files of another project apply
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// finalizeHunt rebuilds the result and the reports from the findings store
// after the agent stage, and returns the operator command's error (its exit
// code is the hunt's verdict).
func finalizeHunt(c *compose.Compose, slug, failOn string, failOnIssues bool) error {
	cliArgs := []string{"buggy-cli", "hunt", "--resume", slug, "--finalize", "--agent-runner", agentRunner, "--yes"}
	if failOn != "" {
		cliArgs = append(cliArgs, "--fail-on", failOn)
	}
	if failOnIssues {
		cliArgs = append(cliArgs, "--fail-on-issues")
	}
	return c.RunInteractive([]string{compose.Profiles.Operator}, "operator", nil, cliArgs...)
}

// claudeAgentStage runs Claude Code on one engagement and closes the run.
// A Claude Code failure does not lose the work: whatever it proved is in the
// findings store, so the run is finalized either way.
func claudeAgentStage(c *compose.Compose, slug, failOn string, failOnIssues, web bool) error {
	if !engagementName.MatchString(slug) {
		return fmt.Errorf("%q is not an engagement name", slug)
	}
	reach := "It can only use Buggy's tools for " + slug + " (no web access)."
	if web {
		reach = "It reaches " + slug + " only through Buggy's tools; it may search the web and " +
			"read public pages through Buggy (--no-web turns that off)."
	}
	ui.Info("Agent stage: Claude Code on this machine, with your Claude sign-in (no model key). " + reach)
	if err := runClaudeFn(c, slug, web); err != nil {
		ui.Warning("Claude Code did not finish cleanly: " + err.Error() +
			". If it is not signed in, run `claude` once and sign in, then `buggy agent " + slug + "`.")
	}
	return finalizeHuntFn(c, slug, failOn, failOnIssues)
}

func controlDir(env map[string]string) string {
	if dir := env["BUGGY_ENGAGEMENT_CONTROL"]; dir != "" {
		return dir
	}
	return filepath.Join(config.BuggyHome(), "control")
}

// newHuntPointer names a one-time file the operator's hunt writes its
// engagement name into; the name is derived there, not here.
func newHuntPointer() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return ".hunt-" + hex.EncodeToString(raw) + ".json", nil
}

// readHuntPointer returns the engagement a finished hunt named, and removes
// the file. An absent or malformed file gives "".
func readHuntPointer(dir, name string) string {
	path := filepath.Join(dir, name)
	defer os.Remove(path)
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Engagement string `json:"engagement"`
	}
	if json.Unmarshal(body, &doc) != nil || !engagementName.MatchString(doc.Engagement) {
		return ""
	}
	return doc.Engagement
}

func runAgent(cmd *cobra.Command, args []string) error {
	slug := args[0]
	if !engagementName.MatchString(slug) {
		return fmt.Errorf("%q is not an engagement name", slug)
	}
	if !claudeAvailable() {
		return errors.New("the `claude` command is not on PATH; install Claude Code and sign in (`claude`), then retry")
	}
	_, env, err := prepareStackFor(cmd, true)
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(filepath.Join(controlDir(env), slug, "roe.json")); statErr != nil {
		return fmt.Errorf("no engagement %q here: run `buggy hunt <target>` first (it maps the target and enforces the scope)", slug)
	}
	if err := startServices(env); err != nil {
		return err
	}
	if err := claudeAgentStage(huntCompose(false), slug, agentFailOn, agentFailOnIssues, !agentNoWeb); err != nil {
		code, message, ok := huntVerdict(err)
		if !ok {
			return err
		}
		ui.Warning(message)
		huntExit(code)
	}
	return nil
}
