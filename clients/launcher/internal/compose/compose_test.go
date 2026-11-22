package compose

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	// filepath.Join is OS-aware (LF separators on Unix, backslash on
	// Windows). Use t.TempDir() to get a valid path on whatever runner
	// executes the test rather than hardcoding a /tmp path that doesn't
	// exist on Windows.
	home := t.TempDir()
	t.Setenv("BUGGY_HOME", home)
	c := New()
	if c.Home != home {
		t.Errorf("Home = %q, want %q", c.Home, home)
	}
	if want := filepath.Join(home, "docker-compose.yml"); c.ComposeFile != want {
		t.Errorf("ComposeFile = %q, want %q", c.ComposeFile, want)
	}
	if want := filepath.Join(home, ".env"); c.EnvFile != want {
		t.Errorf("EnvFile = %q, want %q", c.EnvFile, want)
	}
}

func TestAllProfiles(t *testing.T) {
	profiles := AllProfiles()
	// Every profile the launcher may need to tear down: cli plus the
	// one-off operator shell that writes the control root = 2 profiles =
	// 4 cli args (--profile NAME).
	expected := []string{
		"--profile", "cli",
		"--profile", "operator",
	}
	if len(profiles) != len(expected) {
		t.Fatalf("AllProfiles() len = %d, want %d", len(profiles), len(expected))
	}
	for i, v := range expected {
		if profiles[i] != v {
			t.Errorf("profiles[%d] = %q, want %q", i, profiles[i], v)
		}
	}
}

func TestBaseArgs(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "")
	c := &Compose{
		Home:        "/test",
		ComposeFile: "/test/docker-compose.yml",
		EnvFile:     "/test/.env",
	}
	args := c.baseArgs()
	// Expected shape: ["compose", "-p", "buggy", "-f",
	//                  "/test/docker-compose.yml", "--env-file", "/test/.env"]
	// `-p buggy` is explicit so every caller targets the same compose
	// project; compose's no-`-p` default (the dir basename) drifts the
	// moment any caller passes `-p X` themselves.
	want := []string{
		"compose",
		"-p", "buggy",
		"-f", "/test/docker-compose.yml",
		"--env-file", "/test/.env",
	}
	if len(args) != len(want) {
		t.Fatalf("baseArgs len = %d (%v); want %d (%v)", len(args), args, len(want), want)
	}
	for i, v := range want {
		if args[i] != v {
			t.Errorf("args[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBaseArgs_StackNameOverridesProjectName(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "stack2")
	c := &Compose{
		Home:        "/test",
		ComposeFile: "/test/docker-compose.yml",
		EnvFile:     "/test/.env",
	}
	args := c.baseArgs()
	if args[2] != "buggy-stack2" {
		t.Errorf("expected -p buggy-stack2 for BUGGY_STACK_NAME=stack2; got args=%v", args)
	}
}

func TestImageTag(t *testing.T) {
	tests := map[string]string{
		"v1.0.21":  "1.0.21",
		"1.0.21":   "1.0.21",
		" latest ": "latest",
	}
	for input, want := range tests {
		if got := imageTag(input); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", input, got, want)
		}
	}
}

// ---- NewWithFile, overlays and the argv builders ----

func TestNewWithFile_ResolvesNamesAgainstTheHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BUGGY_HOME", home)
	outside := filepath.Join(t.TempDir(), "elsewhere.yml")

	c := NewWithFile(LiteFile, LabFile, outside)
	if want := filepath.Join(home, "docker-compose.lite.yml"); c.ComposeFile != want {
		t.Errorf("ComposeFile = %q, want %q", c.ComposeFile, want)
	}
	wantOverlays := []string{filepath.Join(home, "docker-compose.lab.yml"), outside}
	if !reflect.DeepEqual(c.Overlays, wantOverlays) {
		t.Errorf("Overlays = %v, want %v", c.Overlays, wantOverlays)
	}
	if want := filepath.Join(home, ".env"); c.EnvFile != want {
		t.Errorf("EnvFile = %q, want %q", c.EnvFile, want)
	}
	wantFiles := append([]string{c.ComposeFile}, wantOverlays...)
	if got := c.Files(); !reflect.DeepEqual(got, wantFiles) {
		t.Errorf("Files() = %v, want %v", got, wantFiles)
	}

	// Control: New() is still the full stack, with nothing layered on it.
	full := New()
	if full.Overlays != nil {
		t.Errorf("New() Overlays = %v; want none", full.Overlays)
	}
	if want := filepath.Join(home, "docker-compose.yml"); full.ComposeFile != want {
		t.Errorf("New().ComposeFile = %q, want %q", full.ComposeFile, want)
	}
}

func TestBaseArgs_OverlaysFollowTheBaseFileInOrder(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "")
	c := &Compose{
		Home:        "/test",
		ComposeFile: "/test/docker-compose.lite.yml",
		EnvFile:     "/test/.env",
		Overlays:    []string{"/test/docker-compose.lab.yml", "/test/docker-compose.demo.yml"},
	}
	want := []string{
		"compose",
		"-p", "buggy",
		"-f", "/test/docker-compose.lite.yml",
		"--env-file", "/test/.env",
		"-f", "/test/docker-compose.lab.yml",
		"-f", "/test/docker-compose.demo.yml",
	}
	if got := c.baseArgs(); !reflect.DeepEqual(got, want) {
		t.Errorf("baseArgs = %v\n       want %v", got, want)
	}
}

func testStack() *Compose {
	return &Compose{Home: "/test", ComposeFile: "/test/docker-compose.lite.yml", EnvFile: "/test/.env"}
}

var testStackBase = []string{"compose", "-p", "buggy", "-f", "/test/docker-compose.lite.yml", "--env-file", "/test/.env"}

func TestUpArgs(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "")
	t.Setenv("BUGGY_STARTUP_TIMEOUT_SECONDS", "")
	c := testStack()

	// Without services this is exactly what Up(profiles...) has always run.
	wantUp := append(append([]string{}, testStackBase...),
		"--profile", "cli", "up", "-d", "--no-build", "--wait", "--wait-timeout", "600")
	if got := c.UpArgs([]string{"cli"}); !reflect.DeepEqual(got, wantUp) {
		t.Errorf("UpArgs(cli) = %v\n          want %v", got, wantUp)
	}

	wantServices := append(append([]string{}, testStackBase...),
		"up", "-d", "--no-build", "--wait", "--wait-timeout", "600", "pipeline", "pipeline-mcp")
	if got := c.UpArgs(nil, "pipeline", "pipeline-mcp"); !reflect.DeepEqual(got, wantServices) {
		t.Errorf("UpArgs(services) = %v\n               want %v", got, wantServices)
	}

	t.Setenv("BUGGY_STARTUP_TIMEOUT_SECONDS", "45")
	if got := c.UpArgs(nil, "pipeline"); got[len(got)-2] != "45" {
		t.Errorf("--wait-timeout must follow BUGGY_STARTUP_TIMEOUT_SECONDS; got %v", got)
	}
}

func TestRunArgs(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "")
	c := testStack()
	want := append(append([]string{}, testStackBase...),
		"--profile", "operator", "run", "--rm", "-e", "A=1", "-e", "B=2", "-e", "C=3",
		"operator", "python", "-m", "buggy.cli", "--help")
	env := map[string]string{"C": "3", "A": "1", "B": "2"}
	for range 20 { // map order is random; the argv must not be
		got := c.RunArgs([]string{"operator"}, "operator", env, "python", "-m", "buggy.cli", "--help")
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("RunArgs = %v\n   want %v", got, want)
		}
	}
	for _, arg := range c.RunArgs(nil, "operator", nil) {
		if arg == "--no-build" {
			t.Error("`compose run` does not accept --no-build")
		}
	}
}

func TestDownAndExecArgs(t *testing.T) {
	t.Setenv("BUGGY_STACK_NAME", "")
	c := testStack()
	wantDown := append(append(append([]string{}, testStackBase...), AllProfiles()...), "down")
	if got := c.DownArgs(); !reflect.DeepEqual(got, wantDown) {
		t.Errorf("DownArgs = %v\n    want %v", got, wantDown)
	}
	for _, arg := range c.DownArgs() {
		if arg == "--volumes" || arg == "-v" {
			t.Error("Down must keep the named volumes (recon data); only DownAndPurge removes them")
		}
	}
	wantExec := append(append([]string{}, testStackBase...), "exec", "-T", "pipeline", "python", "-V")
	if got := c.ExecArgs("pipeline", "python", "-V"); !reflect.DeepEqual(got, wantExec) {
		t.Errorf("ExecArgs = %v\n    want %v", got, wantExec)
	}
}

func TestMissingFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BUGGY_HOME", home)
	c := NewWithFile(LiteFile, LabFile, DemoFile)
	if got := c.MissingFiles(); !reflect.DeepEqual(got, c.Files()) {
		t.Fatalf("empty home: MissingFiles = %v, want all of %v", got, c.Files())
	}
	for _, name := range []string{LiteFile, DemoFile} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("services: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := c.MissingFiles(), []string{filepath.Join(home, LabFile)}; !reflect.DeepEqual(got, want) {
		t.Errorf("MissingFiles = %v, want %v", got, want)
	}
	if err := os.WriteFile(filepath.Join(home, LabFile), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.MissingFiles(); len(got) != 0 {
		t.Errorf("all files present: MissingFiles = %v, want none", got)
	}
}

func TestComposeImageTag(t *testing.T) {
	home := t.TempDir()
	c := &Compose{Home: home}
	t.Setenv("BUGGY_VERSION", "")
	if got := c.ImageTag(nil); got != "stable" {
		t.Errorf("nothing set: ImageTag = %q, want stable", got)
	}
	if got := c.ImageTag(map[string]string{"BUGGY_VERSION": "1.2.3"}); got != "1.2.3" {
		t.Errorf(".env only: ImageTag = %q, want 1.2.3", got)
	}
	t.Setenv("BUGGY_VERSION", "2.0.0")
	if got := c.ImageTag(map[string]string{"BUGGY_VERSION": "1.2.3"}); got != "2.0.0" {
		t.Errorf("the process environment wins over .env: ImageTag = %q, want 2.0.0", got)
	}
	if err := os.WriteFile(filepath.Join(home, ".version"), []byte("v3.1.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.ImageTag(map[string]string{"BUGGY_VERSION": "1.2.3"}); got != "3.1.4" {
		t.Errorf("the .version marker wins: ImageTag = %q, want 3.1.4", got)
	}
}

// envValue returns the last value of key in a child environment (later
// entries win, as in exec.Cmd), and whether the key is present at all.
func envValue(env []string, key string) (string, bool) {
	value, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value, found = v, true
		}
	}
	return value, found
}

// unsetImagePrefix removes BUGGY_IMAGE_PREFIX for the rest of the test and
// restores the caller's value afterwards.
func unsetImagePrefix(t *testing.T) {
	t.Helper()
	t.Setenv("BUGGY_IMAGE_PREFIX", "") // registers the restore
	os.Unsetenv("BUGGY_IMAGE_PREFIX")
}

func TestImagePrefix(t *testing.T) {
	prev := DefaultImagePrefix
	t.Cleanup(func() { DefaultImagePrefix = prev })
	DefaultImagePrefix = "ghcr.io/default/"

	// The shell wins, even when it is explicitly empty.
	t.Setenv("BUGGY_IMAGE_PREFIX", "ghcr.io/shell/")
	if got := ImagePrefix(map[string]string{"BUGGY_IMAGE_PREFIX": "ghcr.io/dotenv/"}); got != "ghcr.io/shell/" {
		t.Errorf("shell value: got %q", got)
	}
	t.Setenv("BUGGY_IMAGE_PREFIX", "")
	if got := ImagePrefix(nil); got != "" {
		t.Errorf("explicit empty: got %q", got)
	}

	unsetImagePrefix(t)
	if got := ImagePrefix(map[string]string{"BUGGY_IMAGE_PREFIX": "ghcr.io/dotenv/"}); got != "ghcr.io/dotenv/" {
		t.Errorf(".env value: got %q", got)
	}
	if got := ImagePrefix(map[string]string{"BUGGY_IMAGE_PREFIX": ""}); got != "" {
		t.Errorf(".env empty: got %q", got)
	}
	if got := ImagePrefix(nil); got != "ghcr.io/default/" {
		t.Errorf("default: got %q", got)
	}
}

func TestComposeEnv_ImagePrefix(t *testing.T) {
	prev := DefaultImagePrefix
	t.Cleanup(func() { DefaultImagePrefix = prev })
	home := t.TempDir()
	t.Setenv("BUGGY_HOME", home)
	unsetImagePrefix(t)
	c := &Compose{Home: home, EnvFile: filepath.Join(home, ".env")}

	// A development build adds nothing: compose resolves the bare names.
	DefaultImagePrefix = ""
	if _, ok := envValue(c.composeEnv(), "BUGGY_IMAGE_PREFIX"); ok {
		t.Errorf("development build set BUGGY_IMAGE_PREFIX")
	}

	// A release build supplies its registry when nothing else does.
	DefaultImagePrefix = "ghcr.io/owner/"
	if v, _ := envValue(c.composeEnv(), "BUGGY_IMAGE_PREFIX"); v != "ghcr.io/owner/" {
		t.Errorf("release default: got %q", v)
	}

	// ...but never over the operator's .env, which compose reads itself.
	if err := os.WriteFile(c.EnvFile, []byte("BUGGY_IMAGE_PREFIX=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := envValue(c.composeEnv(), "BUGGY_IMAGE_PREFIX"); ok {
		t.Errorf("overrode the .env value")
	}
}
