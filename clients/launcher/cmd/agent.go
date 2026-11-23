package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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
//
// The stage is several short attempts, not one long one (agent_runs.go): when
// an attempt ends with calls left and leads still open, a fresh session starts
// with those leads. Then a disprover session argues each agent-made finding is
// false before the run is finalized.
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

	// The bridge's per-run settings (see buggy/agent_bridge.py).
	runIDEnvKey    = "BUGGY_AGENT_RUN_ID"
	sessionEnvKey  = "BUGGY_AGENT_SESSION"
	attemptEnvKey  = "BUGGY_AGENT_ATTEMPT"
	attemptsEnvKey = "BUGGY_AGENT_ATTEMPTS"
	shareEnvKey    = "BUGGY_AGENT_CALL_SHARE"
	recordsEnvKey  = "BUGGY_AGENT_RECORDS"

	roleAgent   = "agent"
	roleSkeptic = "skeptic"
)

// noWebFlagHelp is the help of --no-web on `buggy agent` and `buggy hunt`.
const noWebFlagHelp = "Claude Code agent stage: no web search and no research_fetch (no public-internet lookups)"

// attemptsFlagHelp is the help of the attempts flag on `buggy agent` and `buggy hunt`.
const attemptsFlagHelp = "Claude Code agent stage: most short attempts, each in a fresh session with its own share of the tool-call budget"

// claudePrompt is all the launcher says; the instructions come from the
// bridge's engagement_brief tool, built from the enforced scope.
const claudePrompt = "Call the engagement_brief tool of the buggy server, then carry out the " +
	"engagement it describes using only that server's tools (web search, when you have it, is " +
	"for public documentation only). Work until candidates_next has nothing left for you or " +
	"the tools tell you to stop, then give your final summary."

// claudeContinuePrompt starts a later attempt: the brief lists the open leads.
const claudeContinuePrompt = "Call the engagement_brief tool of the buggy server. This is a " +
	"later attempt in a fresh session: the brief lists the leads an earlier attempt left open " +
	"and says that its 'cannot be done' conclusions are unproven. Carry on with those leads " +
	"using only that server's tools until candidates_next has nothing left for you or the " +
	"tools tell you to stop, then give your final summary."

// skepticPrompt starts the disprover; it has no web and no tool that sends a request.
const skepticPrompt = "Call the engagement_brief tool of the buggy server: it lists agent-made " +
	"findings and your role, which is to argue each one is false. Judge every one with " +
	"finding_challenge, then give one line per finding: id and verdict."

const claudeSystem = "You are running unattended as the testing agent of an authorized " +
	"security engagement. The buggy tool server enforces the scope and holds anything " +
	"state-changing for the operator; treat every refusal as final and never ask for approval " +
	"or credentials."

const skepticSystem = "You are running unattended as the disprover of an authorized " +
	"security engagement. You read evidence; you cannot send requests. Concede a finding only " +
	"when its recorded evidence shows it, and never ask for approval or credentials."

var engagementName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`)

// Seams for tests.
var (
	claudeLookPath = exec.LookPath
	runClaudeFn    = runClaude
	finalizeHuntFn = finalizeHunt
	bridgeStatusFn = bridgeStatus
)

var (
	agentFailOn       string
	agentFailOnIssues bool
	agentNoWeb        bool
	agentAttempts     int
)

var agentCmd = &cobra.Command{
	Use:   "agent ENGAGEMENT",
	Short: "Run the agent stage of an engagement with Claude Code (no model key)",
	Long: "Runs the agent stage of an engagement that `buggy hunt` already mapped, using " +
		"Claude Code on this machine with your own Claude sign-in. No model key is stored " +
		"in Buggy. Claude Code only gets Buggy's tools for this one engagement, plus web " +
		"search for public documentation (--no-web turns it off); scope, approvals, rate " +
		"limits and the audit ledger stay enforced by the stack. The stage is up to " +
		"--attempts short sessions while leads stay open, then a disprover session argues " +
		"each agent-made finding is false before the reports are built.",
	Args: cobra.ExactArgs(1),
	RunE: runAgent,
}

func init() {
	agentCmd.Flags().StringVar(&agentFailOn, "fail-on", "", "Exit 10 when an exploit-verified finding is at or above: critical|high|medium|low|info")
	agentCmd.Flags().BoolVar(&agentFailOnIssues, "fail-on-issues", false, "With --fail-on: also count known issues from the recon report")
	agentCmd.Flags().BoolVar(&agentNoWeb, "no-web", false, noWebFlagHelp)
	agentCmd.Flags().IntVar(&agentAttempts, "attempts", defaultAttempts, attemptsFlagHelp)
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

// claudeRun is one Claude Code session of the agent stage.
type claudeRun struct {
	Role     string // roleAgent or roleSkeptic
	RunID    string
	Session  string
	Attempt  int
	Attempts int
	Share    int // the run's tool-call cap; 0: the bridge's own budget
	Web      bool
}

// bridgeEnv is what the bridge container is told about this run.
func (r claudeRun) bridgeEnv() map[string]string {
	env := map[string]string{}
	if r.RunID != "" {
		env[runIDEnvKey] = r.RunID
	}
	if r.Session != "" {
		env[sessionEnvKey] = r.Session
	}
	if r.Attempt > 0 {
		env[attemptEnvKey] = strconv.Itoa(r.Attempt)
	}
	if r.Attempts > 0 {
		env[attemptsEnvKey] = strconv.Itoa(r.Attempts)
	}
	if r.Share > 0 {
		env[shareEnvKey] = strconv.Itoa(r.Share)
	}
	if !r.Web || r.Role == roleSkeptic {
		env[webEnvKey] = "off"
	}
	return env
}

// claudeMCPConfig is the MCP configuration handed to Claude Code: one server,
// started by running the bridge in a one-off operator container of this
// stack. The compose command and its environment are the launcher's own, so
// the bridge joins exactly the stack `buggy hunt` started. Without web access
// the bridge is told (-e BUGGY_AGENT_WEB=off) to leave research_fetch out.
//
// recordsDir, when set, is the host folder `<audit>/<engagement>/agent`; it is
// mounted writable (the rest of the audit root stays read-only in the operator
// container) so the bridge can keep its call log and lease.
func claudeMCPConfig(c *compose.Compose, slug string, run claudeRun, recordsDir string) ([]byte, error) {
	bridge := []string{"python", "-m", "buggy.agent_bridge", "--engagement", slug}
	if run.Role == roleSkeptic {
		bridge = append(bridge, "--role", roleSkeptic)
	}
	args := bridgeRunArgs(c, run.bridgeEnv(), recordsDir, bridge...)
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

// recordsMount is where the records folder is mounted in the operator container.
const recordsMount = "/agent-records"

// bridgeRunArgs is the compose argv of a one-off operator container running a
// bridge command, with the records folder mounted writable when there is one.
func bridgeRunArgs(c *compose.Compose, env map[string]string, recordsDir string, command ...string) []string {
	if recordsDir != "" {
		withRecords := map[string]string{recordsEnvKey: recordsMount}
		for k, v := range env {
			withRecords[k] = v
		}
		env = withRecords
	}
	args := c.RunCapturedArgs([]string{compose.Profiles.Operator}, "operator", env, command...)
	if recordsDir != "" {
		args = withRunFlags(args, "-v", recordsDir+":"+recordsMount)
	}
	return args
}

// withRunFlags inserts flags of `compose run` right after its `--rm -T`.
func withRunFlags(args []string, flags ...string) []string {
	for i := 1; i < len(args); i++ {
		if args[i] == "-T" && args[i-1] == "--rm" {
			out := append([]string{}, args[:i+1]...)
			out = append(out, flags...)
			return append(out, args[i+1:]...)
		}
	}
	return args
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
// allowed are the bridge's and, with web access, the search. The output is
// JSON so the launcher can record tokens, cost and time per session.
func claudeArgs(configPath string, web bool) []string {
	return claudeArgsFor(configPath, claudeRun{Role: roleAgent, Attempt: 1, Web: web})
}

func claudeArgsFor(configPath string, run claudeRun) []string {
	web := run.Web && run.Role != roleSkeptic
	builtins, allowed := "", "mcp__"+bridgeServer
	if web {
		builtins, allowed = webSearchTool, allowed+","+webSearchTool
	}
	prompt, system := claudePrompt, claudeSystem
	switch {
	case run.Role == roleSkeptic:
		prompt, system = skepticPrompt, skepticSystem
	case run.Attempt > 1:
		prompt = claudeContinuePrompt
	}
	return []string{
		"-p", prompt,
		"--output-format", "json",
		"--mcp-config", configPath,
		"--strict-mcp-config",
		"--tools", builtins,
		"--allowedTools", allowed,
		"--append-system-prompt", system,
	}
}

// claudeResult is what one Claude Code session reported (--output-format json).
// Every field is optional: a missing one is left out of the records.
type claudeResult struct {
	Type           string       `json:"type,omitempty"`
	Subtype        string       `json:"subtype,omitempty"`
	IsError        *bool        `json:"is_error,omitempty"`
	NumTurns       *int         `json:"num_turns,omitempty"`
	DurationMS     *float64     `json:"duration_ms,omitempty"`
	DurationAPIMS  *float64     `json:"duration_api_ms,omitempty"`
	TotalCostUSD   *float64     `json:"total_cost_usd,omitempty"`
	SessionID      string       `json:"session_id,omitempty"`
	TerminalReason string       `json:"terminal_reason,omitempty"`
	StopReason     string       `json:"stop_reason,omitempty"`
	Usage          *claudeUsage `json:"usage,omitempty"`
	Result         string       `json:"-"`
	// Wall is the time the launcher measured around the session.
	Wall time.Duration `json:"-"`
}

type claudeUsage struct {
	InputTokens              *int64 `json:"input_tokens,omitempty"`
	OutputTokens             *int64 `json:"output_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`
}

// parseClaudeOutput reads the JSON result Claude Code prints with
// --output-format json. Output that is not that JSON gives ok == false.
func parseClaudeOutput(out []byte) (claudeResult, bool) {
	text := bytes.TrimSpace(out)
	// The result is the last JSON object on stdout.
	if i := bytes.LastIndex(text, []byte("\n{")); i >= 0 {
		text = text[i+1:]
	}
	var res claudeResult
	var body struct {
		Result string `json:"result"`
	}
	if len(text) == 0 || json.Unmarshal(text, &res) != nil || json.Unmarshal(text, &body) != nil {
		return claudeResult{}, false
	}
	res.Result = body.Result
	return res, res.Type == "result" || res.Usage != nil || res.TotalCostUSD != nil
}

func runClaude(c *compose.Compose, slug string, run claudeRun, recordsDir string) (claudeResult, error) {
	body, err := claudeMCPConfig(c, slug, run, recordsDir)
	if err != nil {
		return claudeResult{}, err
	}
	dir, err := os.MkdirTemp("", "buggy-agent-")
	if err != nil {
		return claudeResult{}, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return claudeResult{}, err
	}
	cmd := exec.Command(claudeBinary, claudeArgsFor(path, run)...)
	cmd.Dir = dir // an empty folder: no project settings or files of another project apply
	cmd.Stdin = nil
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	started := time.Now()
	runErr := cmd.Run()
	res, ok := parseClaudeOutput(stdout.Bytes())
	res.Wall = time.Since(started)
	switch {
	case ok && strings.TrimSpace(res.Result) != "":
		fmt.Println(strings.TrimSpace(res.Result))
	case !ok && stdout.Len() > 0:
		os.Stdout.Write(stdout.Bytes())
	}
	return res, runErr
}

// finalizeHunt rebuilds the result and the reports from the findings store
// after the agent stage, and returns the operator command's error (its exit
// code is the hunt's verdict).
func finalizeHunt(c *compose.Compose, slug, failOn string, failOnIssues bool, disprover string) error {
	cliArgs := []string{"buggy-cli", "hunt", "--resume", slug, "--finalize", "--agent-runner", agentRunner, "--yes"}
	if disprover != "" {
		cliArgs = append(cliArgs, "--disprover", disprover)
	}
	if failOn != "" {
		cliArgs = append(cliArgs, "--fail-on", failOn)
	}
	if failOnIssues {
		cliArgs = append(cliArgs, "--fail-on-issues")
	}
	return c.RunInteractive([]string{compose.Profiles.Operator}, "operator", nil, cliArgs...)
}

// agentStageOptions are the settings of one Claude Code agent stage.
type agentStageOptions struct {
	FailOn       string
	FailOnIssues bool
	Web          bool
	Attempts     int
	// AuditDir is the host's audit root; the agent records go in <AuditDir>/<engagement>/agent.
	AuditDir string
}

// claudeAgentStage runs Claude Code on one engagement and closes the run.
// A Claude Code failure does not lose the work: whatever it proved is in the
// findings store, so the run is finalized either way.
func claudeAgentStage(c *compose.Compose, slug string, opts agentStageOptions) error {
	if !engagementName.MatchString(slug) {
		return fmt.Errorf("%q is not an engagement name", slug)
	}
	reach := "It can only use Buggy's tools for " + slug + " (no web access)."
	if opts.Web {
		reach = "It reaches " + slug + " only through Buggy's tools; it may search the web and " +
			"read public pages through Buggy (--no-web turns that off)."
	}
	ui.Info("Agent stage: Claude Code on this machine, with your Claude sign-in (no model key). " + reach)
	disprover := runAgentSessions(c, slug, opts)
	return finalizeHuntFn(c, slug, opts.FailOn, opts.FailOnIssues, disprover)
}

func controlDir(env map[string]string) string {
	if dir := env["BUGGY_ENGAGEMENT_CONTROL"]; dir != "" {
		return dir
	}
	return filepath.Join(config.BuggyHome(), "control")
}

// auditDir is the host's audit root, as the stack mounts it.
func auditDir(env map[string]string) string {
	if dir := env["BUGGY_ENGAGEMENT_AUDIT"]; dir != "" {
		return dir
	}
	return filepath.Join(config.BuggyHome(), "audit")
}

// newID is a random hex name for a hunt pointer, a session or a run.
func newID(bytesLong int) (string, error) {
	raw := make([]byte, bytesLong)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// newHuntPointer names a one-time file the operator's hunt writes its
// engagement name into; the name is derived there, not here.
func newHuntPointer() (string, error) {
	id, err := newID(12)
	if err != nil {
		return "", err
	}
	return ".hunt-" + id + ".json", nil
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
	opts := agentStageOptions{
		FailOn: agentFailOn, FailOnIssues: agentFailOnIssues, Web: !agentNoWeb,
		Attempts: agentAttempts, AuditDir: auditDir(env),
	}
	if err := claudeAgentStage(huntCompose(false), slug, opts); err != nil {
		code, message, ok := huntVerdict(err)
		if !ok {
			return err
		}
		ui.Warning(message)
		huntExit(code)
	}
	return nil
}
