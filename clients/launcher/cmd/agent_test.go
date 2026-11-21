package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
)

func TestUseClaudeCode(t *testing.T) {
	cases := []struct {
		name                           string
		mode                           string
		lite, noAgent, noModel, claude bool
		want                           bool
		wantErr                        string
	}{
		{name: "auto: no model, claude installed", mode: "auto", noModel: true, claude: true, want: true},
		{name: "default is auto", mode: "", noModel: true, claude: true, want: true},
		{name: "auto: a model is configured", mode: "auto", claude: true},
		{name: "auto: claude not installed", mode: "auto", noModel: true},
		{name: "auto: --no-agent wins", mode: "auto", noAgent: true, noModel: true, claude: true},
		{name: "auto: --lite has no gateway", mode: "auto", lite: true, noModel: true, claude: true},
		{name: "builtin never uses it", mode: "builtin", noModel: true, claude: true},
		{name: "explicit, even with a model", mode: "claude-code", claude: true, want: true},
		{name: "explicit without claude", mode: "claude-code", wantErr: "not on PATH"},
		{name: "explicit with --lite", mode: "claude-code", lite: true, claude: true, wantErr: "full stack"},
		{name: "explicit with --no-agent", mode: "claude-code", noAgent: true, claude: true, wantErr: "contradict"},
		{name: "unknown mode", mode: "gpt", wantErr: "must be auto, builtin or claude-code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := useClaudeCode(tc.mode, tc.lite, tc.noAgent, tc.noModel, tc.claude)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%v, %v), want (%v, nil)", got, err, tc.want)
			}
		})
	}
}

// Claude Code must get nothing but the bridge: no built-in tool, no other
// MCP server of this machine, and only the bridge's tools allowed.
func TestClaudeArgs_OnlyTheBridge(t *testing.T) {
	args := claudeArgs("/tmp/x/mcp.json")
	at := func(flag string) string {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) {
			t.Fatalf("%s missing in %v", flag, args)
		}
		return args[i+1]
	}
	if at("--tools") != "" {
		t.Errorf("built-in tools are not disabled: --tools %q", at("--tools"))
	}
	if at("--allowedTools") != "mcp__buggy" {
		t.Errorf("--allowedTools = %q", at("--allowedTools"))
	}
	if at("--mcp-config") != "/tmp/x/mcp.json" || !slices.Contains(args, "--strict-mcp-config") {
		t.Errorf("the MCP configuration is not exclusive: %v", args)
	}
	if !strings.Contains(at("-p"), "engagement_brief") {
		t.Errorf("the prompt does not send the agent to the brief: %q", at("-p"))
	}
	for _, forbidden := range []string{"--dangerously-skip-permissions", "bypassPermissions"} {
		if slices.Contains(args, forbidden) {
			t.Errorf("%s must never be passed", forbidden)
		}
	}
}

func TestClaudeMCPConfig_StartsTheBridgeInTheOperatorContainer(t *testing.T) {
	stackHome(t)
	body, err := claudeMCPConfig(dockerShaped(huntCompose(false)), "acme")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Servers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Servers) != 1 {
		t.Fatalf("want exactly one server, got %v", doc.Servers)
	}
	server := doc.Servers["buggy"]
	if server.Command != "docker" {
		t.Errorf("command = %q", server.Command)
	}
	tail := []string{"run", "--rm", "-T", "operator", "python", "-m", "buggy.agent_bridge", "--engagement", "acme"}
	if len(server.Args) < len(tail) || !slices.Equal(server.Args[len(server.Args)-len(tail):], tail) {
		t.Errorf("args do not end with the bridge command:\n got %v\nwant ...%v", server.Args, tail)
	}
	if !slices.Contains(server.Args, "operator") || !slices.Contains(server.Args, "--profile") {
		t.Errorf("the operator profile is missing: %v", server.Args)
	}
	// The file is read by another program: it names the stack and nothing
	// else. No secret, and nothing of the launcher's own environment.
	for name := range server.Env {
		if !bridgeEnvName(name) {
			t.Errorf("%s does not belong in the MCP config", name)
		}
	}
}

func TestBridgeEnvName(t *testing.T) {
	for _, name := range []string{"BUGGY_HOME", "BUGGY_STACK_NAME", "BUGGY_VERSION", "COMPOSE_PROJECT_NAME", "DOCKER_HOST"} {
		if !bridgeEnvName(name) {
			t.Errorf("%s is needed to select the stack", name)
		}
	}
	for _, name := range []string{
		"BUGGY_STACK_MCP_TOKEN", "SANDBOX_TOKEN", "BUGGY_AUDIT_HMAC_KEY", "ANTHROPIC_API_KEY",
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "BUGGY_NEO4J_PASSWORD", "PATH", "HOME",
	} {
		if bridgeEnvName(name) {
			t.Errorf("%s must not be written into the MCP config", name)
		}
	}
}

func TestHuntOperatorCommand_ClaudeCodeStopsBeforeBuiltinAgents(t *testing.T) {
	argv := huntOperatorCommand([]string{"example.com"}, huntFlags{mode: "enforce", claudeCode: true})
	if !slices.Contains(argv, "--no-agent") {
		t.Errorf("--no-agent missing: %v", argv)
	}
	if !(huntFlags{claudeCode: true}).skipsModelAuth() {
		t.Error("a Claude Code hunt must not stop at the model wizard")
	}
}

func TestHuntPointer_RoundTripAndRejects(t *testing.T) {
	dir := t.TempDir()
	name, err := newHuntPointer()
	if err != nil || !strings.HasPrefix(name, ".hunt-") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("pointer name %q, %v", name, err)
	}
	other, _ := newHuntPointer()
	if other == name {
		t.Fatal("pointer names repeat")
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"engagement": "acme-prod"}`)
	if got := readHuntPointer(dir, name); got != "acme-prod" {
		t.Errorf("got %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Error("the pointer file was not removed")
	}
	for _, body := range []string{`{"engagement": "../etc"}`, `{"engagement": ""}`, `not json`, `{}`} {
		write(body)
		if got := readHuntPointer(dir, name); got != "" {
			t.Errorf("%s gave %q", body, got)
		}
	}
	if got := readHuntPointer(dir, name); got != "" {
		t.Errorf("an absent file gave %q", got)
	}
}

func TestClaudeAgentStage_FinalizesEvenWhenClaudeFails(t *testing.T) {
	stackHome(t)
	prevRun, prevFinal := runClaudeFn, finalizeHuntFn
	t.Cleanup(func() { runClaudeFn, finalizeHuntFn = prevRun, prevFinal })

	var ran, finalized []string
	runClaudeFn = func(_ *compose.Compose, slug string) error {
		ran = append(ran, slug)
		return errors.New("exit status 1")
	}
	finalizeHuntFn = func(_ *compose.Compose, slug, failOn string, issues bool) error {
		finalized = append(finalized, slug+"|"+failOn)
		return nil
	}
	if err := claudeAgentStage(huntCompose(false), "acme", "high", false); err != nil {
		t.Fatalf("a Claude Code failure must not fail the run by itself: %v", err)
	}
	if !slices.Equal(ran, []string{"acme"}) || !slices.Equal(finalized, []string{"acme|high"}) {
		t.Errorf("ran %v, finalized %v", ran, finalized)
	}

	ran, finalized = nil, nil
	if err := claudeAgentStage(huntCompose(false), "../x", "", false); err == nil {
		t.Error("a path was accepted as an engagement name")
	}
	if len(ran)+len(finalized) != 0 {
		t.Error("something ran for an invalid engagement name")
	}
}
