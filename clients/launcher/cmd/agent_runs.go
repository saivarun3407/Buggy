package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
)

// The Claude Code agent stage as several short sessions, then a disprover.
//
//  1. Ask the bridge for the engagement's state (`--status`): halted or not,
//     the tool-call budget, how many leads are still open.
//  2. Run attempt 1 with its share of the budget. After each attempt ask again;
//     start another attempt in a fresh session while leads are open, calls are
//     left and attempts remain (nextAttempt). A later attempt's brief lists
//     the open leads and says earlier "cannot be done" conclusions are unproven.
//  3. If agent-made findings were verified, run the disprover (--role skeptic),
//     which can only read evidence and record a verdict per finding.
//
// Every session gets a line in <audit>/<engagement>/agent/agent-runs.jsonl:
// tokens, cost (when Claude Code reports one), wall time and tool calls. The
// launcher hands its numbers to the status call that follows the session,
// which appends the line inside the operator container: on Linux the audit
// root belongs to the containers' user, so this machine may not write it.

const (
	defaultAttempts = 3
	// minAttemptCalls: a share smaller than this is not worth a fresh session.
	minAttemptCalls = 15
	// The disprover's call cap: a few calls per finding, within bounds.
	skepticCallsPerFinding = 8
	skepticMinCalls        = 20
	skepticMaxCalls        = 160
)

// stageStatus is what `python -m buggy.agent_bridge --status` prints.
type stageStatus struct {
	Halted      bool        `json:"halted"`
	HaltReason  string      `json:"halt_reason"`
	BudgetTotal int         `json:"budget_total"`
	CallsUsed   int         `json:"calls_used"`
	CallsLeft   int         `json:"calls_left"`
	Runs        []runCounts `json:"runs"`
	OpenLeads   int         `json:"open_leads"`
	ToChallenge int         `json:"to_challenge"`
	Errors      []string    `json:"errors"`
	// Recorded is the agent-runs line written for the record passed in.
	Recorded    *runCounts `json:"recorded"`
	RecordError string     `json:"record_error"`
}

// runCounts are a run's calls; the recorded line uses the same names
// (tool_calls there, calls in the status's run list).
type runCounts struct {
	Run         string `json:"run"`
	Calls       int    `json:"calls"`
	ToolCalls   int    `json:"tool_calls"`
	Refused     int    `json:"refused"`
	SigninCalls int    `json:"signin_calls"`
}

func (s stageStatus) run(id string) runCounts {
	if s.Recorded != nil && s.Recorded.Run == id {
		r := *s.Recorded
		r.Calls = max(r.Calls, r.ToolCalls)
		return r
	}
	for _, r := range s.Runs {
		if r.Run == id {
			return r
		}
	}
	return runCounts{Run: id}
}

// bridgeStatus asks the bridge, in a one-off operator container, for the
// state; with a record, the status call also appends it to agent-runs.jsonl.
func bridgeStatus(c *compose.Compose, slug, session, recordsDir string, record []byte) (stageStatus, error) {
	command := []string{"python", "-m", "buggy.agent_bridge", "--engagement", slug, "--status", "--session", session}
	if len(record) > 0 {
		command = append(command, "--record", string(record))
	}
	bin := c.Runtime.Bin
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.Command(bin, bridgeRunArgs(c, nil, recordsDir, command...)...)
	cmd.Env = c.Env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr // the bridge logs a lot at import; shown only on failure
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(stderr.String())
		if len(tail) > 400 {
			tail = tail[len(tail)-400:]
		}
		return stageStatus{}, fmt.Errorf("the bridge's status failed (%w): %s", err, tail)
	}
	return parseStatus(stdout.Bytes())
}

func parseStatus(out []byte) (stageStatus, error) {
	text := bytes.TrimSpace(out)
	if i := bytes.LastIndex(text, []byte("\n")); i >= 0 {
		text = text[i+1:]
	}
	var st stageStatus
	if err := json.Unmarshal(text, &st); err != nil {
		return stageStatus{}, fmt.Errorf("the bridge's status is not JSON: %w", err)
	}
	return st, nil
}

// attemptShare is the tool-call cap of the next attempt: what is left, split
// evenly over the attempts that may still run.
func attemptShare(callsLeft, attemptsLeft int) int {
	if attemptsLeft < 1 || callsLeft < 1 {
		return 0
	}
	return callsLeft / attemptsLeft
}

// nextAttempt decides whether another attempt starts after attempt `done` of
// `attempts`, and with which share. It is the whole "keep going" rule.
func nextAttempt(st stageStatus, statusErr, runErr error, done, attempts int) (share int, why string) {
	switch {
	case runErr != nil:
		return 0, "Claude Code did not finish cleanly"
	case statusErr != nil:
		return 0, "the engagement's state could not be read: " + statusErr.Error()
	case st.Halted:
		return 0, "the operator halted the engagement"
	case done >= attempts:
		return 0, fmt.Sprintf("all %d attempts were used", attempts)
	case st.OpenLeads == 0 && len(st.Errors) > 0:
		return 0, "the open leads could not be listed"
	case st.OpenLeads == 0:
		return 0, "no lead is left open"
	}
	share = attemptShare(st.CallsLeft, attempts-done)
	if share < minAttemptCalls {
		return 0, fmt.Sprintf("the tool-call budget is spent (%d left)", st.CallsLeft)
	}
	return share, ""
}

// skepticShare is the disprover's call cap for n findings.
func skepticShare(n int) int {
	share := n*skepticCallsPerFinding + 10
	if share < skepticMinCalls {
		return skepticMinCalls
	}
	if share > skepticMaxCalls {
		return skepticMaxCalls
	}
	return share
}

// agentRunRecord is one line of agent-runs.jsonl.
type agentRunRecord struct {
	At          float64       `json:"at"`
	Engagement  string        `json:"engagement"`
	Session     string        `json:"session"`
	Run         string        `json:"run"`
	Role        string        `json:"role"`
	Attempt     int           `json:"attempt"`
	CallBudget  int           `json:"call_budget"`
	WallSeconds float64       `json:"wall_seconds"`
	Exit        string        `json:"exit"`
	Error       string        `json:"error,omitempty"`
	ToolCalls   int           `json:"tool_calls"`
	Refused     int           `json:"refused"`
	SigninCalls int           `json:"signin_calls"`
	Claude      *claudeResult `json:"claude,omitempty"`
}

func newAgentRunRecord(slug string, run claudeRun, started time.Time, res claudeResult, ok bool, runErr error, counts runCounts) agentRunRecord {
	rec := agentRunRecord{
		At: float64(started.UnixMilli()) / 1000, Engagement: slug, Session: run.Session,
		Run: run.RunID, Role: run.Role, Attempt: run.Attempt, CallBudget: run.Share,
		WallSeconds: res.Wall.Round(100 * time.Millisecond).Seconds(), Exit: "ok",
		ToolCalls: counts.Calls, Refused: counts.Refused, SigninCalls: counts.SigninCalls,
	}
	if runErr != nil {
		rec.Exit, rec.Error = "error", runErr.Error()
	}
	if ok {
		rec.Claude = &res
	}
	return rec
}

// sessionLine is the short summary printed after each session.
func sessionLine(rec agentRunRecord) string {
	parts := []string{fmt.Sprintf("%d tool calls (%d refused, %d on sign-in)", rec.ToolCalls, rec.Refused, rec.SigninCalls)}
	if rec.Claude != nil && rec.Claude.Usage != nil {
		u := rec.Claude.Usage
		in := deref(u.InputTokens) + deref(u.CacheReadInputTokens) + deref(u.CacheCreationInputTokens)
		parts = append(parts, fmt.Sprintf("%s input and %s output tokens", tokens(in), tokens(deref(u.OutputTokens))))
	}
	if rec.Claude != nil && rec.Claude.TotalCostUSD != nil {
		parts = append(parts, fmt.Sprintf("$%.2f as reported by Claude Code", *rec.Claude.TotalCostUSD))
	} else {
		parts = append(parts, "cost not reported")
	}
	parts = append(parts, time.Duration(rec.WallSeconds*float64(time.Second)).Round(time.Second).String())
	label := "attempt " + fmt.Sprint(rec.Attempt)
	if rec.Role == roleSkeptic {
		label = "disprover"
	}
	return "Claude Code " + label + ": " + strings.Join(parts, ", ")
}

func deref(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func tokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 10_000:
		return fmt.Sprintf("%dk", n/1000)
	}
	return fmt.Sprint(n)
}

// recordsDirFor is the host folder the bridge keeps its call log, lease and
// session lines in, mounted writable into its container. It is made here when
// this machine may; otherwise the container runtime makes it when mounting.
func recordsDirFor(audit, slug string) string {
	if audit == "" {
		return ""
	}
	dir := filepath.Join(audit, slug, "agent")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// runSession runs one Claude Code session, has its line recorded and prints
// its summary.
func runSession(c *compose.Compose, slug string, run claudeRun, records string) sessionOutcome {
	started := time.Now()
	res, runErr := runClaudeFn(c, slug, run, records)
	ok := res.Usage != nil || res.TotalCostUSD != nil || res.Type != ""
	rec := newAgentRunRecord(slug, run, started, res, ok, runErr, runCounts{Run: run.RunID})
	line, _ := json.Marshal(rec)
	st, statusErr := bridgeStatusFn(c, slug, run.Session, records, line)
	switch {
	case statusErr != nil:
		ui.Warning("This session's cost and calls were not recorded: " + statusErr.Error())
	case st.RecordError != "":
		ui.Warning("This session's cost and calls were not recorded: " + st.RecordError)
	}
	if statusErr == nil {
		counts := st.run(run.RunID)
		rec.ToolCalls, rec.Refused, rec.SigninCalls = counts.Calls, counts.Refused, counts.SigninCalls
	}
	ui.DimText(sessionLine(rec))
	return sessionOutcome{status: st, statusErr: statusErr, runErr: runErr}
}

// sessionOutcome is how a session ended and the engagement's state after it.
type sessionOutcome struct {
	status    stageStatus
	statusErr error // the state could not be read
	runErr    error // Claude Code did not finish cleanly
}

// runAgentSessions runs the attempts and the disprover, and returns what the
// disprover did, for the finalize step: ran, nothing, skipped or failed.
func runAgentSessions(c *compose.Compose, slug string, opts agentStageOptions) string {
	attempts := opts.Attempts
	if attempts < 1 {
		attempts = 1
	}
	session, err := newID(8)
	if err != nil {
		session = fmt.Sprint(time.Now().UnixNano())
	}
	records := recordsDirFor(opts.AuditDir, slug)

	st, statusErr := bridgeStatusFn(c, slug, session, records, nil)
	if statusErr == nil && st.Halted {
		ui.Warning("Engagement " + slug + " is halted by the operator (" + st.HaltReason + "): no agent runs. Lift it with `buggy-cli halt " + slug + " --clear`.")
		return "skipped"
	}
	share := 0 // without a status the bridge's own budget applies, in one attempt
	if statusErr == nil {
		share = attemptShare(st.CallsLeft, attempts)
	} else {
		ui.Warning("The engagement's state could not be read (" + statusErr.Error() + "); running one attempt.")
		attempts = 1
	}

	for attempt := 1; ; attempt++ {
		runID, _ := newID(8)
		run := claudeRun{Role: roleAgent, RunID: runID, Session: session, Attempt: attempt,
			Attempts: attempts, Share: share, Web: opts.Web}
		if attempt > 1 {
			ui.Info(fmt.Sprintf("Attempt %d of %d: %d lead(s) still open and %d tool calls left; a fresh session gets %d of them.",
				attempt, attempts, st.OpenLeads, st.CallsLeft, share))
		}
		out := runSession(c, slug, run, records)
		if out.runErr != nil {
			ui.Warning("Claude Code did not finish cleanly: " + out.runErr.Error() +
				". If it is not signed in, run `claude` once and sign in, then `buggy agent " + slug + "`.")
		}
		st, statusErr = out.status, out.statusErr
		next, why := nextAttempt(st, statusErr, out.runErr, attempt, attempts)
		if next == 0 {
			ui.DimText("Agent stage over: " + why + ".")
			break
		}
		share = next
	}
	return runDisprover(c, slug, session, records, st, statusErr)
}

// disproverNote is what a hunt whose agents were not Claude Code says about the
// disprover pass, which only the Claude Code path runs; "" when no agent ran.
func disproverNote(f huntFlags, claude bool) string {
	if f.noAgent || f.lite || f.planOnly {
		return ""
	}
	if !claude {
		return "Disprover pass skipped: the `claude` command is not installed, so agent-made findings were not challenged before grading."
	}
	return "Disprover pass skipped: it runs with Claude Code as the agent (`--agent claude-code`); Buggy's own agents' findings were graded without it."
}

// runDisprover runs the skeptic session when agent-made findings were verified.
func runDisprover(c *compose.Compose, slug, session, records string, st stageStatus, statusErr error) string {
	switch {
	case statusErr != nil:
		ui.Warning("Disprover pass skipped: the findings could not be listed (" + statusErr.Error() + ").")
		return "skipped"
	case st.Halted:
		ui.Warning("Disprover pass skipped: the engagement is halted.")
		return "skipped"
	case st.ToChallenge == 0:
		ui.DimText("Disprover pass: no agent-made finding to judge.")
		return "nothing"
	}
	ui.Info(fmt.Sprintf("Disprover pass: a second Claude Code session argues each of %d agent-made finding(s) is false; "+
		"'false_positive' or 'undetermined' keeps a finding out of the report until you override it.", st.ToChallenge))
	runID, _ := newID(8)
	run := claudeRun{Role: roleSkeptic, RunID: runID, Session: session, Attempt: 1, Attempts: 1,
		Share: skepticShare(st.ToChallenge)}
	if err := runSession(c, slug, run, records).runErr; err != nil {
		ui.Warning("The disprover did not finish cleanly: " + err.Error() + ". Findings it did not judge are graded as usual.")
		return "failed"
	}
	return "ran"
}
