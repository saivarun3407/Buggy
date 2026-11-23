package cmd

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
)

// stageRecorder holds what a faked agent stage did.
type stageRecorder struct {
	runs     []claudeRun
	records  []agentRunRecord
	statuses int
}

// fakeStage replaces the seams of the agent stage. The bridge's status answers
// with statuses in order (the last one repeats); Claude Code succeeds with no
// output unless the test sets runClaudeFn itself.
func fakeStage(t *testing.T, statuses []stageStatus) *stageRecorder {
	t.Helper()
	prevRun, prevFinal, prevStatus := runClaudeFn, finalizeHuntFn, bridgeStatusFn
	t.Cleanup(func() { runClaudeFn, finalizeHuntFn, bridgeStatusFn = prevRun, prevFinal, prevStatus })
	rec := &stageRecorder{}
	bridgeStatusFn = func(_ *compose.Compose, _, _, _ string, record []byte) (stageStatus, error) {
		if len(record) > 0 {
			var r agentRunRecord
			if err := json.Unmarshal(record, &r); err != nil {
				t.Fatalf("the record is not JSON: %s", record)
			}
			rec.records = append(rec.records, r)
		}
		i := min(rec.statuses, len(statuses)-1)
		rec.statuses++
		return statuses[i], nil
	}
	runClaudeFn = func(_ *compose.Compose, _ string, run claudeRun, _ string) (claudeResult, error) {
		rec.runs = append(rec.runs, run)
		return claudeResult{}, nil
	}
	finalizeHuntFn = func(*compose.Compose, string, string, bool, string) error { return nil }
	return rec
}

func TestNextAttempt(t *testing.T) {
	open := stageStatus{BudgetTotal: 300, CallsUsed: 100, CallsLeft: 200, OpenLeads: 5}
	cases := []struct {
		name      string
		st        stageStatus
		statusErr error
		runErr    error
		done      int
		want      int
		why       string
	}{
		{name: "leads open and calls left", st: open, done: 1, want: 100},
		{name: "last attempt gets the rest", st: open, done: 2, want: 200},
		{name: "all attempts used", st: open, done: 3, why: "all 3 attempts"},
		{name: "nothing left open", st: stageStatus{CallsLeft: 200}, done: 1, why: "no lead is left open"},
		{name: "leads unknown", st: stageStatus{CallsLeft: 200, Errors: []string{"capture down"}}, done: 1, why: "could not be listed"},
		{name: "budget spent", st: stageStatus{CallsLeft: 20, OpenLeads: 3}, done: 1, why: "budget is spent"},
		{name: "halted", st: stageStatus{Halted: true, CallsLeft: 200, OpenLeads: 3}, done: 1, why: "halted"},
		{name: "claude failed", st: open, runErr: errors.New("exit 1"), done: 1, why: "did not finish"},
		{name: "status failed", st: open, statusErr: errors.New("no docker"), done: 1, why: "could not be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			share, why := nextAttempt(tc.st, tc.statusErr, tc.runErr, tc.done, 3)
			if share != tc.want || (tc.why != "" && !strings.Contains(why, tc.why)) || (tc.want > 0 && why != "") {
				t.Errorf("got (%d, %q), want (%d, ...%q)", share, why, tc.want, tc.why)
			}
		})
	}
}

func TestShares(t *testing.T) {
	if got := attemptShare(300, 3); got != 100 {
		t.Errorf("attemptShare(300, 3) = %d", got)
	}
	if attemptShare(10, 0) != 0 || attemptShare(0, 3) != 0 {
		t.Error("no attempts or no calls must give no share")
	}
	for n, want := range map[int]int{0: skepticMinCalls, 1: skepticMinCalls, 5: 50, 100: skepticMaxCalls} {
		if got := skepticShare(n); got != want {
			t.Errorf("skepticShare(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestAgentSessions_KeepGoingWhileLeadsAreOpenThenDisprove(t *testing.T) {
	stackHome(t)
	rec := fakeStage(t, []stageStatus{
		{BudgetTotal: 300, CallsLeft: 300, OpenLeads: 6},                                                      // before
		{BudgetTotal: 300, CallsUsed: 100, CallsLeft: 200, OpenLeads: 3, Runs: []runCounts{{Calls: 100}}},     // after 1
		{BudgetTotal: 300, CallsUsed: 150, CallsLeft: 150, OpenLeads: 0, ToChallenge: 2},                      // after 2
		{BudgetTotal: 300, CallsUsed: 150, CallsLeft: 150, OpenLeads: 0, ToChallenge: 2, Runs: []runCounts{}}, // after skeptic
	})
	got := runAgentSessions(huntCompose(false), "acme", agentStageOptions{Web: true, Attempts: 3})
	if got != "ran" {
		t.Errorf("disprover = %q", got)
	}
	if len(rec.runs) != 3 {
		t.Fatalf("want two attempts and a disprover, got %+v", rec.runs)
	}
	first, second, skeptic := rec.runs[0], rec.runs[1], rec.runs[2]
	if first.Attempt != 1 || first.Share != 100 || second.Attempt != 2 || second.Share != 100 {
		t.Errorf("attempts and shares: %+v %+v", first, second)
	}
	if first.Session == "" || first.Session != second.Session || first.RunID == second.RunID {
		t.Errorf("attempts share a session and have their own run ids: %+v %+v", first, second)
	}
	if skeptic.Role != roleSkeptic || skeptic.Share != skepticShare(2) || skeptic.Web {
		t.Errorf("disprover run: %+v", skeptic)
	}
	if len(rec.records) != 3 || rec.records[2].Role != roleSkeptic || rec.records[0].Engagement != "acme" {
		t.Errorf("every session is recorded: %+v", rec.records)
	}
}

func TestAgentSessions_HaltedEngagementRunsNothing(t *testing.T) {
	stackHome(t)
	rec := fakeStage(t, []stageStatus{{Halted: true, HaltReason: "stop", CallsLeft: 300, OpenLeads: 4}})
	if got := runAgentSessions(huntCompose(false), "acme", agentStageOptions{Attempts: 3}); got != "skipped" {
		t.Errorf("disprover = %q", got)
	}
	if len(rec.runs) != 0 {
		t.Errorf("a halted engagement started Claude Code: %+v", rec.runs)
	}
}

func TestAgentSessions_HaltDuringAnAttemptStopsTheRest(t *testing.T) {
	stackHome(t)
	rec := fakeStage(t, []stageStatus{
		{CallsLeft: 300, OpenLeads: 6},
		{Halted: true, CallsLeft: 250, OpenLeads: 6, ToChallenge: 3},
	})
	if got := runAgentSessions(huntCompose(false), "acme", agentStageOptions{Attempts: 3}); got != "skipped" {
		t.Errorf("disprover = %q", got)
	}
	if len(rec.runs) != 1 {
		t.Errorf("runs after a halt: %+v", rec.runs)
	}
}

func TestAgentSessions_NoAgentFindingsNoDisprover(t *testing.T) {
	stackHome(t)
	rec := fakeStage(t, []stageStatus{{CallsLeft: 300, OpenLeads: 2}, {CallsLeft: 250, OpenLeads: 0}})
	if got := runAgentSessions(huntCompose(false), "acme", agentStageOptions{Attempts: 3}); got != "nothing" {
		t.Errorf("disprover = %q", got)
	}
	if len(rec.runs) != 1 || rec.runs[0].Role != roleAgent {
		t.Errorf("runs: %+v", rec.runs)
	}
}

func TestStatusRun_PrefersTheRecordedLine(t *testing.T) {
	st := stageStatus{
		Runs:     []runCounts{{Run: "r1", Calls: 3}},
		Recorded: &runCounts{Run: "r1", ToolCalls: 7, SigninCalls: 2},
	}
	if got := st.run("r1"); got.Calls != 7 || got.SigninCalls != 2 {
		t.Errorf("got %+v", got)
	}
	if got := (stageStatus{Runs: st.Runs}).run("r1"); got.Calls != 3 {
		t.Errorf("got %+v", got)
	}
}

func TestBridgeRunArgs_MountsTheRecordsOnlyWhenThereAreSome(t *testing.T) {
	stackHome(t)
	c := dockerShaped(huntCompose(false))
	with := bridgeRunArgs(c, nil, "/r", "python", "-m", "buggy.agent_bridge", "--status")
	if i := slices.Index(with, "/r:/agent-records"); i < 1 || with[i-1] != "-v" {
		t.Errorf("no mount: %v", with)
	}
	if !slices.Contains(with, "BUGGY_AGENT_RECORDS=/agent-records") {
		t.Errorf("the bridge is not told where the records are: %v", with)
	}
	without := bridgeRunArgs(c, nil, "", "python")
	if slices.Contains(without, "-v") || slices.ContainsFunc(without, func(a string) bool { return strings.Contains(a, "AGENT_RECORDS") }) {
		t.Errorf("a mount without a folder: %v", without)
	}
}

func TestAgentSessions_WithoutStatusOneAttemptWithTheBridgesBudget(t *testing.T) {
	stackHome(t)
	rec := fakeStage(t, []stageStatus{{}})
	bridgeStatusFn = func(*compose.Compose, string, string, string, []byte) (stageStatus, error) {
		return stageStatus{}, errors.New("no docker")
	}
	if got := runAgentSessions(huntCompose(false), "acme", agentStageOptions{Attempts: 3}); got != "skipped" {
		t.Errorf("disprover = %q", got)
	}
	if len(rec.runs) != 1 || rec.runs[0].Share != 0 || rec.runs[0].Attempts != 1 {
		t.Errorf("runs: %+v", rec.runs)
	}
}

// A result as Claude Code 2.1 prints it with --output-format json (trimmed).
const claudeJSONSample = `{"type":"result","subtype":"success","is_error":false,"duration_ms":1897,` +
	`"duration_api_ms":697,"num_turns":1,"result":"ok","session_id":"2a3e","total_cost_usd":0.0196818,` +
	`"usage":{"input_tokens":2,"cache_creation_input_tokens":2433,"cache_read_input_tokens":649,` +
	`"output_tokens":4,"service_tier":"standard"},"terminal_reason":"completed","stop_reason":"end_turn"}`

func TestParseClaudeOutput(t *testing.T) {
	res, ok := parseClaudeOutput([]byte("noise from a hook\n" + claudeJSONSample + "\n"))
	if !ok || res.Result != "ok" || res.TotalCostUSD == nil || *res.TotalCostUSD != 0.0196818 {
		t.Fatalf("parsed %+v, %v", res, ok)
	}
	if res.Usage == nil || deref(res.Usage.CacheReadInputTokens) != 649 || deref(res.Usage.OutputTokens) != 4 {
		t.Errorf("usage %+v", res.Usage)
	}
	// Missing fields stay missing; text output is not a result.
	res, ok = parseClaudeOutput([]byte(`{"type":"result","result":"done"}`))
	if !ok || res.Usage != nil || res.TotalCostUSD != nil {
		t.Errorf("a result without usage: %+v, %v", res, ok)
	}
	if _, ok := parseClaudeOutput([]byte("All done.\n")); ok {
		t.Error("plain text was taken for a result")
	}
}

func TestAgentRunRecord_WhatIsHandedOverAndSummarised(t *testing.T) {
	res, _ := parseClaudeOutput([]byte(claudeJSONSample))
	res.Wall = 95 * time.Second
	run := claudeRun{Role: roleAgent, RunID: "r1", Session: "s1", Attempt: 2, Share: 100}
	rec := newAgentRunRecord("acme", run, time.Unix(1700000000, 0), res, true, nil,
		runCounts{Run: "r1", Calls: 42, Refused: 3, SigninCalls: 5})
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	claude := doc["claude"].(map[string]any)
	usage := claude["usage"].(map[string]any)
	// The field names the Python summary reads (buggy/agent_records.py).
	if usage["input_tokens"] != 2.0 || usage["cache_read_input_tokens"] != 649.0 || claude["total_cost_usd"] != 0.0196818 {
		t.Errorf("claude section: %v", claude)
	}
	if doc["tool_calls"] != 42.0 || doc["signin_calls"] != 5.0 || doc["wall_seconds"] != 95.0 || doc["run"] != "r1" {
		t.Errorf("record: %v", doc)
	}
	if _, has := claude["result"]; has {
		t.Error("the agent's summary text is not stored with the cost")
	}
	line := sessionLine(rec)
	for _, want := range []string{"attempt 2", "42 tool calls (3 refused, 5 on sign-in)", "3084 input", "$0.02", "1m35s"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q lacks %q", line, want)
		}
	}
	noCost := newAgentRunRecord("acme", claudeRun{Role: roleSkeptic}, time.Now(), claudeResult{}, false, errors.New("exit 1"), runCounts{})
	if noCost.Claude != nil || noCost.Exit != "error" || !strings.Contains(sessionLine(noCost), "cost not reported") {
		t.Errorf("a session without output: %+v %q", noCost, sessionLine(noCost))
	}
}

func TestClaudeMCPConfig_RunSettingsAndRecordsMount(t *testing.T) {
	stackHome(t)
	run := claudeRun{Role: roleSkeptic, RunID: "r1", Session: "s1", Attempt: 1, Attempts: 1, Share: 40, Web: true}
	body, err := claudeMCPConfig(dockerShaped(huntCompose(false)), "acme", run, "/home/me/.buggy/audit/acme/agent")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Servers map[string]struct {
			Args []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	args := doc.Servers["buggy"].Args
	for _, want := range []string{"BUGGY_AGENT_RUN_ID=r1", "BUGGY_AGENT_SESSION=s1", "BUGGY_AGENT_CALL_SHARE=40", "BUGGY_AGENT_WEB=off", "BUGGY_AGENT_RECORDS=/agent-records"} {
		if i := slices.Index(args, want); i < 1 || args[i-1] != "-e" {
			t.Errorf("%s missing: %v", want, args)
		}
	}
	if i := slices.Index(args, "/home/me/.buggy/audit/acme/agent:/agent-records"); i < 1 || args[i-1] != "-v" {
		t.Errorf("the records folder is not mounted: %v", args)
	}
	tail := []string{"operator", "python", "-m", "buggy.agent_bridge", "--engagement", "acme", "--role", "skeptic"}
	if !slices.Equal(args[len(args)-len(tail):], tail) {
		t.Errorf("args do not end with the disprover's bridge command: %v", args)
	}
}

func TestClaudeArgsFor_RolesAndAttempts(t *testing.T) {
	skeptic := claudeArgsFor("/tmp/m.json", claudeRun{Role: roleSkeptic, Web: true})
	if flagValue(t, skeptic, "--tools") != "" || flagValue(t, skeptic, "--allowedTools") != "mcp__buggy" {
		t.Errorf("the disprover has no web: %v", skeptic)
	}
	if !strings.Contains(flagValue(t, skeptic, "-p"), "finding_challenge") {
		t.Errorf("the disprover is not told its job: %v", skeptic)
	}
	later := claudeArgsFor("/tmp/m.json", claudeRun{Role: roleAgent, Attempt: 2, Web: true})
	if !strings.Contains(flagValue(t, later, "-p"), "unproven") {
		t.Errorf("a later attempt is not told earlier conclusions are unproven: %v", later)
	}
	if flagValue(t, later, "--output-format") != "json" {
		t.Error("the session's usage is not asked for")
	}
}

func TestDisproverNote(t *testing.T) {
	if disproverNote(huntFlags{noAgent: true}, true) != "" || disproverNote(huntFlags{lite: true}, false) != "" {
		t.Error("no agent ran, so there is nothing to say")
	}
	if !strings.Contains(disproverNote(huntFlags{}, false), "not installed") {
		t.Error("a missing claude is not named")
	}
	if !strings.Contains(disproverNote(huntFlags{}, true), "--agent claude-code") {
		t.Error("the way to get the pass is not named")
	}
}

func TestParseStatus(t *testing.T) {
	st, err := parseStatus([]byte("log line\n" + `{"halted": false, "budget_total": 300, "calls_used": 12, "calls_left": 288, "open_leads": 4, "to_challenge": 1, "runs": [{"run": "r1", "calls": 12, "refused": 2, "signin_calls": 1}]}` + "\n"))
	if err != nil || st.CallsLeft != 288 || st.OpenLeads != 4 || st.run("r1").SigninCalls != 1 || st.run("r9").Calls != 0 {
		t.Errorf("%+v, %v", st, err)
	}
	if _, err := parseStatus([]byte("Traceback ...")); err == nil {
		t.Error("a crash was read as a status")
	}
}
