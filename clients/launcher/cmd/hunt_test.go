package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/runtime"
	"github.com/saivarun3407/buggy/clients/launcher/internal/updater"
	"github.com/spf13/cobra"
)

// stackHome points the launcher at an empty Buggy home and neutralises every
// environment variable that changes a compose argv, so the argv tests below
// compare against literals.
func stackHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("BUGGY_HOME", home)
	t.Setenv("BUGGY_STACK_NAME", "")
	t.Setenv("BUGGY_OPSCONTROL_SOCK_HOST", "")
	t.Setenv("BUGGY_STARTUP_TIMEOUT_SECONDS", "")
	return home
}

// dockerShaped pins the runtime to the default (`docker compose ...`), so an
// argv does not depend on which container runtime this machine has.
func dockerShaped(c *compose.Compose) *compose.Compose {
	c.Runtime = runtime.Runtime{}
	return c
}

// operatorArgv is the full `compose run` argv runHunt executes for flags.
func operatorArgv(targets []string, flags huntFlags) []string {
	return dockerShaped(huntCompose(flags.lite)).RunArgs(
		[]string{compose.Profiles.Operator}, "operator", nil,
		huntOperatorCommand(targets, flags)...)
}

// Golden: the argv of `buggy hunt` without --lite, exactly as it was before
// --lite existed. If this test needs editing, the full-stack hunt changed.
func TestHuntArgv_WithoutLiteIsUnchanged(t *testing.T) {
	home := stackHome(t)
	base := []string{
		"compose", "-p", "buggy",
		"-f", filepath.Join(home, "docker-compose.yml"),
		"--env-file", filepath.Join(home, ".env"),
		"--profile", "operator", "run", "--rm", "operator",
	}

	cases := []struct {
		name    string
		targets []string
		flags   huntFlags
		command []string
	}{
		{
			name:    "defaults",
			targets: []string{"example.com"},
			flags:   huntFlags{mode: "enforce"},
			command: []string{"buggy-cli", "hunt", "example.com", "--mode", "enforce"},
		},
		{
			name:    "every flag",
			targets: []string{"a.example", "https://b.example"},
			flags: huntFlags{
				scope:          []string{"*.example", "10.0.0.0/8"},
				exclude:        []string{"admin.example"},
				includeSubs:    true,
				scopeFile:      "/tmp/scope.json",
				instruction:    "focus auth",
				mode:           "warn",
				planOnly:       true,
				nonInteractive: true,
				yes:            true,
				noAgent:        true,
				lab:            true,
				internal:       true,
				allowSandbox:   true,
				portScan:       true,
				rps:            7,
			},
			command: []string{
				"buggy-cli", "hunt", "a.example", "https://b.example",
				"--scope", "*.example", "--scope", "10.0.0.0/8",
				"--exclude", "admin.example",
				"--include-subdomains",
				"--scope-file", "/tmp/scope.json",
				"--instruction", "focus auth",
				"--mode", "warn",
				"--plan-only",
				"--non-interactive",
				"--yes", "--no-agent", "--lab", "--internal", "--allow-sandbox-network", "--port-scan",
				"--rps", "7",
			},
		},
		{
			name:    "no-agent only when asked",
			targets: []string{"example.com"},
			flags:   huntFlags{mode: "enforce", yes: true, noAgent: true},
			command: []string{"buggy-cli", "hunt", "example.com", "--mode", "enforce", "--yes", "--no-agent"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := append(append([]string{}, base...), tc.command...)
			if got := operatorArgv(tc.targets, tc.flags); !reflect.DeepEqual(got, want) {
				t.Errorf("argv changed:\n got %v\nwant %v", got, want)
			}
		})
	}

	// Without --lite and without --no-agent the agents run: the flag is absent.
	if slices.Contains(operatorArgv([]string{"example.com"}, huntFlags{mode: "enforce"}), "--no-agent") {
		t.Error("--no-agent passed although neither --no-agent nor --lite was set")
	}
}

func TestHuntArgv_LiteUsesTheLiteFileAndForcesNoAgent(t *testing.T) {
	home := stackHome(t)
	want := []string{
		"compose", "-p", "buggy",
		"-f", filepath.Join(home, "docker-compose.lite.yml"),
		"--env-file", filepath.Join(home, ".env"),
		"--profile", "operator", "run", "--rm", "operator",
		"python", "-m", "buggy.cli", "hunt", "example.com", "--mode", "enforce", "--no-agent",
	}
	got := operatorArgv([]string{"example.com"}, huntFlags{mode: "enforce", lite: true})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lite argv:\n got %v\nwant %v", got, want)
	}
	// The slim image has no `buggy-cli` script, and the full file is not used.
	if slices.Contains(got, "buggy-cli") || slices.Contains(got, filepath.Join(home, "docker-compose.yml")) {
		t.Errorf("lite argv refers to the full stack: %v", got)
	}

	// --lite --no-agent passes the flag once, and keeps every other flag.
	both := huntOperatorCommand([]string{"example.com"}, huntFlags{mode: "enforce", lite: true, noAgent: true, yes: true, rps: 3})
	wantBoth := []string{"python", "-m", "buggy.cli", "hunt", "example.com", "--mode", "enforce", "--yes", "--no-agent", "--rps", "3"}
	if !reflect.DeepEqual(both, wantBoth) {
		t.Errorf("lite + no-agent command:\n got %v\nwant %v", both, wantBoth)
	}
}

func TestHuntLite_StartsOnlyThePipelineServices(t *testing.T) {
	home := stackHome(t)
	want := []string{
		"compose", "-p", "buggy",
		"-f", filepath.Join(home, "docker-compose.lite.yml"),
		"--env-file", filepath.Join(home, ".env"),
		"up", "-d", "--no-build", "--wait", "--wait-timeout", "600",
		"pipeline", "pipeline-mcp",
	}
	got := dockerShaped(huntCompose(true)).UpArgs(nil, liteServices...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lite up argv:\n got %v\nwant %v", got, want)
	}
}

// The lite stack must not inherit the opscontrol overlay: it mounts a socket
// into langgraph, a service the lite file does not have.
func TestHuntLite_NeverAttachesTheOpscontrolOverlay(t *testing.T) {
	home := stackHome(t)
	override := filepath.Join(home, "docker-compose.opscontrol.yml")
	if err := os.WriteFile(override, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUGGY_OPSCONTROL_SOCK_HOST", filepath.Join(home, "ops.sock"))

	if !slices.Contains(operatorArgv([]string{"example.com"}, huntFlags{mode: "enforce"}), override) {
		t.Fatal("control: the full-stack hunt should attach the opscontrol overlay here")
	}
	if slices.Contains(operatorArgv([]string{"example.com"}, huntFlags{mode: "enforce", lite: true}), override) {
		t.Error("the lite hunt attached the opscontrol overlay")
	}
}

func TestHuntLiteFlag_IsWiredAndSaysWhatItCannotDo(t *testing.T) {
	flag := huntCmd.Flags().Lookup("lite")
	if flag == nil {
		t.Fatal("hunt has no --lite flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--lite default = %q, want false", flag.DefValue)
	}
	for _, phrase := range []string{"no model key", "--no-agent", "cannot run side by side"} {
		if !strings.Contains(flag.Usage, phrase) {
			t.Errorf("--lite help does not mention %q: %s", phrase, flag.Usage)
		}
	}

	if currentHuntFlags().lite || currentHuntFlags().skipsModelAuth() {
		t.Fatal("control: --lite must be off by default")
	}
	if err := huntCmd.Flags().Set("lite", "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = huntCmd.Flags().Set("lite", "false") })
	if flags := currentHuntFlags(); !flags.lite || !flags.skipsModelAuth() {
		t.Errorf("after --lite: lite=%v skipsModelAuth=%v, want both true", flags.lite, flags.skipsModelAuth())
	}
}

// stubAuth replaces the model-auth validator with one that always refuses
// and counts how often it was asked.
func stubAuth(t *testing.T) (calls *int, refusal error) {
	t.Helper()
	count := 0
	refusal = errors.New("no model provider is configured")
	prev := validateAuthFn
	validateAuthFn = func(map[string]string) error { count++; return refusal }
	t.Cleanup(func() { validateAuthFn = prev })
	return &count, refusal
}

func TestCheckModelAuth(t *testing.T) {
	// The real validator refuses an environment with no provider at all...
	if err := checkModelAuth(map[string]string{}, false); err == nil {
		t.Fatal("an environment with no model provider passed the auth gate")
	}
	// ...and a run that skips the gate is not asked.
	if err := checkModelAuth(map[string]string{}, true); err != nil {
		t.Fatalf("skipped gate returned %v", err)
	}

	calls, refusal := stubAuth(t)
	if err := checkModelAuth(nil, true); err != nil || *calls != 0 {
		t.Errorf("skip: err=%v calls=%d, want nil and 0", err, *calls)
	}
	if err := checkModelAuth(nil, false); !errors.Is(err, refusal) || *calls != 1 {
		t.Errorf("no skip: err=%v calls=%d, want the refusal and 1", err, *calls)
	}
}

// Runs the real prepareStack up to the first step after the auth gate.
//
// The Buggy home has a .env with no model provider, and PATH has no docker,
// so prepareStack stops at the Docker check - the step right after the gate -
// without running a container, a download or a prompt.
func TestPrepareStack_LiteHuntDoesNotCallAuthValidation(t *testing.T) {
	home := stackHome(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DO_NOT_TRACK", "1") // the telemetry migration never prompts
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("BUGGY_HOME="+home+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, refusal := stubAuth(t)

	// Without --lite the gate runs and its refusal stops the hunt.
	_, _, err := prepareStackFor(huntCmd, huntFlags{mode: "enforce"}.skipsModelAuth())
	if !errors.Is(err, refusal) {
		t.Fatalf("full hunt: err = %v, want the auth refusal", err)
	}
	if *calls != 1 {
		t.Fatalf("full hunt: auth validation ran %d times, want 1", *calls)
	}

	// With --lite the validator is never called, and prepareStack goes on.
	*calls = 0
	_, _, err = prepareStackFor(huntCmd, huntFlags{mode: "enforce", lite: true}.skipsModelAuth())
	if *calls != 0 {
		t.Fatalf("lite hunt: auth validation ran %d times, want 0", *calls)
	}
	if err == nil || errors.Is(err, refusal) || !strings.Contains(err.Error(), "Docker is not installed") {
		t.Fatalf("lite hunt: err = %v, want it to get past the gate to the Docker check", err)
	}

	// prepareStack itself (start, bounty) still enforces the gate.
	*calls = 0
	if _, _, err := prepareStack(huntCmd); !errors.Is(err, refusal) || *calls != 1 {
		t.Fatalf("prepareStack: err=%v calls=%d, want the refusal and 1", err, *calls)
	}
}

func TestEnsureComposeFiles(t *testing.T) {
	home := stackHome(t)
	var refs []string
	download := func(names ...string) func(string, *updater.Release) error {
		return func(ref string, release *updater.Release) error {
			refs = append(refs, ref)
			if release != nil {
				t.Errorf("sync was pinned to a release: %v", release)
			}
			for _, name := range names {
				if err := os.WriteFile(filepath.Join(home, name), []byte("services: {}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		}
	}
	prev := syncConfigFn
	t.Cleanup(func() { syncConfigFn = prev })
	env := map[string]string{"BUGGY_BRANCH": "feature-x"}
	c := huntCompose(true)

	// Missing, and the download does not bring it: an error that names it.
	syncConfigFn = download()
	err := ensureComposeFiles(env, c)
	if err == nil || !strings.Contains(err.Error(), compose.LiteFile) {
		t.Fatalf("file still missing after sync: err = %v, want it named", err)
	}
	// A dev build (version "dev") tracks the configured branch.
	if !reflect.DeepEqual(refs, []string{"feature-x"}) {
		t.Fatalf("sync refs = %v, want [feature-x]", refs)
	}

	// Missing, and the download brings it.
	refs = nil
	syncConfigFn = download(compose.LiteFile)
	if err := ensureComposeFiles(env, c); err != nil {
		t.Fatalf("file downloaded: err = %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("sync ran %d times, want 1", len(refs))
	}

	// Present: nothing is downloaded.
	refs = nil
	if err := ensureComposeFiles(env, c); err != nil || len(refs) != 0 {
		t.Fatalf("file present: err=%v, sync ran %d times; want nil and 0", err, len(refs))
	}

	// A failed download is reported, not swallowed.
	if err := os.Remove(filepath.Join(home, compose.LiteFile)); err != nil {
		t.Fatal(err)
	}
	syncConfigFn = func(string, *updater.Release) error { return errors.New("network down") }
	if err := ensureComposeFiles(env, c); err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("failed sync: err = %v", err)
	}
}

func TestStopCommand_NamesTheLiteFile(t *testing.T) {
	home := stackHome(t)
	got := stopCommand(dockerShaped(huntCompose(true)))
	if !strings.HasPrefix(got, "docker compose -p buggy -f "+filepath.Join(home, "docker-compose.lite.yml")) ||
		!strings.HasSuffix(got, " down") {
		t.Errorf("stopCommand = %q", got)
	}
}

// stubWizard replaces the setup wizard and counts its runs. A run writes a
// configured .env, as the real wizard does, keeping what was there.
func stubWizard(t *testing.T) *int {
	t.Helper()
	prev := runOnboardFn
	t.Cleanup(func() { runOnboardFn = prev })
	calls := 0
	runOnboardFn = func(*cobra.Command, []string) error {
		calls++
		return config.AppendEnvLine(config.EnvPath(), "WIZARD_RAN", "1")
	}
	return &calls
}

// A first recon-only run on a fresh install does not open the model wizard;
// the first run that needs a model does, exactly once.
func TestPrepareStack_FirstLiteRunSkipsTheWizardAndTheNextFullRunOpensIt(t *testing.T) {
	home := filepath.Join(t.TempDir(), "fresh-home")
	t.Setenv("BUGGY_HOME", home)
	t.Setenv("PATH", t.TempDir()) // stop at the Docker check, after the gates
	t.Setenv("DO_NOT_TRACK", "1")
	wizard := stubWizard(t)
	authCalls, _ := stubAuth(t)

	_, _, err := prepareStackFor(huntCmd, huntFlags{mode: "enforce", lite: true}.skipsModelAuth())
	if err == nil || !strings.Contains(err.Error(), "Docker is not installed") {
		t.Fatalf("lite first run: err = %v, want it to reach the Docker check", err)
	}
	if *wizard != 0 || *authCalls != 0 {
		t.Fatalf("lite first run: wizard ran %d times, auth %d times; want 0 and 0", *wizard, *authCalls)
	}
	env, loadErr := config.LoadEnv(filepath.Join(home, ".env"))
	if loadErr != nil || env["BUGGY_HOME"] != home || env[reconOnlyKey] != reconOnlyValue {
		t.Fatalf("lite first run: .env = %v (err %v), want BUGGY_HOME and the recon-only mark", env, loadErr)
	}

	// A second lite run changes nothing and still opens no wizard.
	_, _, _ = prepareStackFor(huntCmd, huntFlags{mode: "enforce", lite: true}.skipsModelAuth())
	if *wizard != 0 {
		t.Fatalf("second lite run opened the wizard")
	}

	// The first run that needs a model opens it once and clears the mark.
	_, _, _ = prepareStack(huntCmd)
	if *wizard != 1 {
		t.Fatalf("full run after a recon-only setup: wizard ran %d times, want 1", *wizard)
	}
	if isReconOnlyEnv() {
		t.Fatalf("the recon-only mark is still set after the wizard")
	}
	_, _, _ = prepareStack(huntCmd)
	if *wizard != 1 {
		t.Fatalf("the wizard ran again on the next full run (%d times)", *wizard)
	}
}

// Control: a fresh install with a command that needs a model opens the wizard.
func TestPrepareStack_FreshFullRunOpensTheWizard(t *testing.T) {
	t.Setenv("BUGGY_HOME", filepath.Join(t.TempDir(), "fresh-home"))
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DO_NOT_TRACK", "1")
	wizard := stubWizard(t)
	stubAuth(t)
	_, _, _ = prepareStack(huntCmd)
	if *wizard != 1 {
		t.Fatalf("fresh full run: wizard ran %d times, want 1", *wizard)
	}
}

// The gate flags reach the operator command after everything a plain hunt
// passes, and --resume needs no target.
func TestHuntOperatorCommand_ResumeAndGateFlags(t *testing.T) {
	got := huntOperatorCommand(nil, huntFlags{mode: "enforce", resume: "acme", failOn: "high", failOnIssues: true, yes: true})
	want := []string{"buggy-cli", "hunt", "--mode", "enforce", "--yes", "--resume", "acme", "--fail-on", "high", "--fail-on-issues"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resume argv:\n got %v\nwant %v", got, want)
	}
	named := huntOperatorCommand([]string{"app.example.com"}, huntFlags{mode: "enforce", engagement: "acme", lite: true})
	if !slices.Contains(named, "--engagement-name") || named[len(named)-1] != "acme" {
		t.Errorf("engagement name not passed: %v", named)
	}
	// Without the new flags nothing is added.
	plain := huntOperatorCommand([]string{"app.example.com"}, huntFlags{mode: "enforce"})
	for _, flag := range []string{"--resume", "--fail-on", "--fail-on-issues", "--engagement-name"} {
		if slices.Contains(plain, flag) {
			t.Errorf("%s passed without being set: %v", flag, plain)
		}
	}

	prev := huntResume
	t.Cleanup(func() { huntResume = prev })
	huntResume = ""
	if err := huntCmd.Args(huntCmd, nil); err == nil {
		t.Error("no target and no --resume was accepted")
	}
	huntResume = "acme"
	if err := huntCmd.Args(huntCmd, nil); err != nil {
		t.Errorf("--resume without a target was refused: %v", err)
	}
}

// exitWith returns the error a command exiting with code produces.
func exitWith(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	if err == nil {
		t.Fatalf("exit %d produced no error", code)
	}
	return fmt.Errorf("docker compose run operator: %w", err)
}

// The hunt's own exit codes are passed through; anything else stays an error.
func TestHuntVerdict(t *testing.T) {
	for _, code := range []int{10, 3, 2} {
		got, message, ok := huntVerdict(exitWith(t, code))
		if !ok || got != code || message == "" {
			t.Errorf("exit %d: got code=%d ok=%v message=%q", code, got, ok, message)
		}
	}
	if _, _, ok := huntVerdict(exitWith(t, 1)); ok {
		t.Error("exit 1 (a crash) was reported as a hunt verdict")
	}
	if _, _, ok := huntVerdict(errors.New("docker not found")); ok {
		t.Error("a start failure was reported as a hunt verdict")
	}
	if _, _, ok := huntVerdict(nil); ok {
		t.Error("success was reported as a failed verdict")
	}
}
