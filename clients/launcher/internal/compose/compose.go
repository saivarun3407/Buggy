package compose

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/opscontrol"
	"github.com/saivarun3407/buggy/clients/launcher/internal/project"
	"github.com/saivarun3407/buggy/clients/launcher/internal/runtime"
)

// Compose files the launcher runs, by their name in the Buggy home.
const (
	// MainFile is the full stack.
	MainFile = "docker-compose.yml"
	// LiteFile is the recon-only stack (pipeline, pipeline-mcp, operator):
	// no model gateway, no agent runtime. It stands alone, and it uses the
	// same service, container, volume and network names as MainFile, so the
	// two cannot run side by side from one Buggy home.
	LiteFile = "docker-compose.lite.yml"
	// LabFile adds the local, intentionally vulnerable practice targets.
	LabFile = "docker-compose.lab.yml"
	// DemoFile makes LiteFile + LabFile a runnable stack for `buggy demo`.
	DemoFile = "docker-compose.demo.yml"
)

// Compose wraps Docker Compose commands for Buggy services.
type Compose struct {
	Home        string
	ComposeFile string
	EnvFile     string
	// Overlays are further compose files layered on ComposeFile, in order.
	Overlays []string
	// Standalone marks a base file that is not the full stack. The
	// launcher-managed opscontrol overlay mounts a socket into the langgraph
	// service, which only the full stack has, so it is never attached here.
	Standalone bool
	// Runtime is the container runtime selected at construction time
	// (docker / podman / nerdctl). Stored so every call uses the same
	// binary + socket and we don't re-probe on every invocation.
	Runtime runtime.Runtime
}

// New creates a Compose instance using the Buggy home directory.
// The container runtime is detected at construction time so every
// subsequent call uses the same binary. Falls back to "docker" if no
// runtime is reachable so existing tests and dev workflows that don't
// have Podman installed keep working unchanged.
func New() *Compose {
	return NewWithFile(MainFile)
}

// NewWithFile is New for another base compose file, with optional overlays
// layered on it in the order given. A relative path is resolved against the
// Buggy home, so NewWithFile(LiteFile) is the lite stack of this install.
func NewWithFile(path string, overlays ...string) *Compose {
	home := config.BuggyHome()
	inHome := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(home, p)
	}
	var layered []string
	for _, overlay := range overlays {
		layered = append(layered, inHome(overlay))
	}
	rt, err := runtime.Detect()
	if err != nil {
		// No runtime available right now — fall back to assuming
		// docker. The user will get a clear error from the first
		// `docker` exec if it's really missing, and the onboard
		// System Check surfaces it well before reaching here.
		rt = runtime.Runtime{Name: "docker", Bin: "docker", ComposeArgs: []string{"compose"}}
	}
	return &Compose{
		Home:        home,
		ComposeFile: inHome(path),
		EnvFile:     filepath.Join(home, ".env"),
		Overlays:    layered,
		Standalone:  filepath.Base(path) != MainFile,
		Runtime:     rt,
	}
}

// Files returns the compose files of this stack: the base file, then the
// overlays in the order compose merges them.
func (c *Compose) Files() []string {
	return append([]string{c.ComposeFile}, c.Overlays...)
}

// MissingFiles returns the files of this stack that are not on disk.
func (c *Compose) MissingFiles() []string {
	var missing []string
	for _, file := range c.Files() {
		if !fileExists(file) {
			missing = append(missing, file)
		}
	}
	return missing
}

// Profiles defines the Docker Compose profile names this launcher
// recognizes. The shipped catalog (cli + every specialist workload)
// is the union — `cli` is always activated by `buggy start`;
// the specialist workloads come up on demand through ADR-0006's
// opscontrol daemon. The launcher keeps the names here as constants
// only so `down` / `stop` can sweep every container regardless of
// which workloads the agent ended up spawning.
var Profiles = struct {
	CLI       string
	Reversing string
	Operator  string
}{
	CLI:       "cli",
	Reversing: "reversing",
	Operator:  "operator",
}

// AllProfiles returns every profile flag the launcher should pass
// to `docker compose down`. Workloads the agent never spawned are
// silently no-ops; the cost of listing them is one cli-arg per
// profile, which beats orphaning containers when an engagement
// brought up an ad-hoc combination of specialists.
func AllProfiles() []string {
	return []string{
		"--profile", Profiles.CLI,
		"--profile", Profiles.Reversing,
		"--profile", Profiles.Operator,
	}
}

// baseArgs returns the common compose arguments for the detected
// runtime. For Docker this is ["compose", "-f", ...]; for Podman 4.4+
// it's the same shape; for the podman-compose wrapper the leading
// "compose" is omitted because the wrapper IS the compose tool.
//
// Defaults to ["compose"] when c.Runtime is the zero value so tests
// that instantiate Compose{} directly (without going through New())
// still produce the Docker-shaped argv.
func (c *Compose) baseArgs() []string {
	prefix := c.Runtime.ComposeArgs
	if prefix == nil && c.Runtime.Bin == "" {
		prefix = []string{"compose"}
	}
	args := append([]string{}, prefix...)
	// `-p` is explicit so the launcher's project name matches what the
	// opscontrol daemon uses on its own compose calls (DockerComposeBackend
	// reads the same helper). Without `-p`, compose defaults to the
	// sanitized basename of $BUGGY_HOME — that agrees by accident in
	// normal flows but breaks the moment any caller passes a different
	// `-p` (CI, manual debugging, …) and produces a "container_name in
	// use by another project" conflict on the next ops_start.
	args = append(args, "-p", opscontrol.ComposeProjectName())
	args = append(args, "-f", c.ComposeFile, "--env-file", c.EnvFile)
	for _, overlay := range c.Overlays {
		args = append(args, "-f", overlay)
	}
	if c.Standalone {
		return args
	}
	// ADR-0006 Sprint 1: include the opscontrol overlay only when
	// the file exists AND the host socket has been bound. Attaching
	// the overlay without BUGGY_OPSCONTROL_SOCK_HOST exported
	// would mount /dev/null into langgraph (the old `:-/dev/null`
	// fallback in the overlay) — that's a wiring bug masquerading
	// as a "daemon unreachable" diagnostic at agent runtime,
	// which is much harder to debug than a missing overlay at boot.
	// EnsureRunning() exports the env var on success; the user-side
	// fallback (no service manager + spawn failed) keeps the overlay
	// out so the boot doesn't silently regress to the broken state.
	if override := filepath.Join(c.Home, "docker-compose.opscontrol.yml"); fileExists(override) &&
		os.Getenv("BUGGY_OPSCONTROL_SOCK_HOST") != "" {
		args = append(args, "-f", override)
	}
	return args
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ContainerName builds the docker container name for a Buggy
// service, mirroring the “${BUGGY_STACK_NAME:+-${BUGGY_STACK_NAME}}“
// template used by docker-compose.yml (#216). Unset/empty → today's
// “buggy-<svc>“ name verbatim; “stack2“ → “buggy-stack2-<svc>“.
// Keeps the Go launcher and YAML naming convention in lockstep so
// “docker exec“/“logs“/“stop“ resolve the right container in
// dual-stack runs.
func ContainerName(svc string) string {
	stack := strings.TrimSpace(os.Getenv("BUGGY_STACK_NAME"))
	if stack == "" {
		return "buggy-" + svc
	}
	return "buggy-" + stack + "-" + svc
}

// readVersion returns the installed version from $BUGGY_HOME/.version,
// or an empty string if the file is missing or unreadable. The launcher
// (install + explicit update) is the single writer; compose falls back to
// :stable (the conservative default channel tag) when the marker is absent.
func (c *Compose) readVersion() string {
	data, err := os.ReadFile(filepath.Join(c.Home, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// composeEnv returns the parent environment with BUGGY_VERSION pinned
// from the .version file plus any runtime-derived env (DOCKER_HOST for
// Podman, etc.). docker compose treats the process environment as
// higher precedence than --env-file, so this overrides any stale value the
// user may have written into .env and avoids the silent `:stable` drift
// that occurs when the variable is unset.
func (c *Compose) composeEnv() []string {
	// Single source of truth for compose interpolation env (STACK_NAME +
	// COMPOSE_PROJECT). The daemon's DockerComposeBackend reads from the
	// same helper so the two never write DIFFERENT container_name
	// values into the SAME compose project. See
	// opscontrol.ComposeCommandEnv() for the rationale.
	env := opscontrol.ComposeCommandEnv()
	if v := c.readVersion(); v != "" {
		env = append(env, "BUGGY_VERSION="+imageTag(v))
	}
	env = append(env, c.imagePrefixEnv()...)
	// Inject DOCKER_HOST for Podman so nested Docker-API clients in
	// containers (testcontainers, kubectl-with-docker-shim) find the
	// Podman socket. No-op for Docker.
	env = c.Runtime.Apply(env)
	return env
}

// run executes a compose command via the detected runtime.
func (c *Compose) run(args []string, interactive bool) error {
	cmdArgs := append(c.baseArgs(), args...)
	cmd := exec.Command(c.Runtime.Bin, cmdArgs...)
	cmd.Env = c.composeEnv()
	if interactive {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s compose %s: %w", c.Runtime.Name, strings.Join(args, " "), err)
	}
	return nil
}

// Up starts services in detached mode and blocks until healthchecks pass.
//
// `--wait` (Docker Compose 2.0+) makes `up` block until each service's compose
// healthcheck transitions to healthy, eliminating the need for the launcher to
// re-implement HTTP polling.
//
// `--wait-timeout` is the single user-facing patience knob. Override via
// BUGGY_STARTUP_TIMEOUT_SECONDS for slower hardware. Default 600s
// covers most environments after measuring 136s LiteLLM cold start in CI.
func (c *Compose) Up(profiles ...string) error {
	return c.run(upArgs(profiles, nil), false)
}

// UpServices is Up for the named services only (and what they depend on).
// It is how a stack with one-off or optional services starts just the
// long-running ones.
func (c *Compose) UpServices(services ...string) error {
	return c.run(upArgs(nil, services), false)
}

// UpArgs returns the full argv (after the runtime binary) that Up and
// UpServices execute.
func (c *Compose) UpArgs(profiles []string, services ...string) []string {
	return append(c.baseArgs(), upArgs(profiles, services)...)
}

func upArgs(profiles, services []string) []string {
	args := []string{}
	for _, p := range profiles {
		args = append(args, "--profile", p)
	}
	args = append(args, "up", "-d", "--no-build", "--wait", "--wait-timeout", startupTimeoutSeconds())
	return append(args, services...)
}

// startupTimeoutSeconds returns the --wait-timeout value as a string.
// User override via BUGGY_STARTUP_TIMEOUT_SECONDS; falls back to 600s.
func startupTimeoutSeconds() string {
	if v := os.Getenv("BUGGY_STARTUP_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return strconv.Itoa(n)
		}
	}
	return "600"
}

// Down stops and removes containers using all profiles for clean teardown.
func (c *Compose) Down() error {
	return c.run(downArgs(), false)
}

// DownArgs returns the full argv (after the runtime binary) that Down
// executes.
func (c *Compose) DownArgs() []string {
	return append(c.baseArgs(), downArgs()...)
}

func downArgs() []string {
	return append(AllProfiles(), "down")
}

// DownAndPurge tears down containers, networks, and named volumes. Used by
// `buggy remove` so a full uninstall doesn't leave gigabytes of
// postgres/neo4j data behind.
func (c *Compose) DownAndPurge() error {
	args := AllProfiles()
	args = append(args, "down", "--volumes", "--remove-orphans")
	return c.run(args, false)
}

// Pull pulls images for services with a version tag. An explicit version
// argument overrides the .version file (used by the updater right after a
// new release lands). Empty version → fall back to whatever .version says.
func (c *Compose) Pull(version string) error {
	cmd := exec.Command(c.Runtime.Bin, append(c.baseArgs(), "pull")...)
	// Base off composeEnv so the stack-name + runtime injections apply
	// here too; an explicit version arg overrides the .version-derived
	// BUGGY_VERSION (later entries win in the child process env).
	env := c.composeEnv()
	if version != "" {
		env = append(env, "BUGGY_VERSION="+imageTag(version))
	}
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s compose pull: %w", c.Runtime.Name, err)
	}
	return nil
}

func imageTag(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(version), "v")
}

// ImageTag returns the tag compose resolves ${BUGGY_VERSION:-stable} to for
// this install: the .version marker, else BUGGY_VERSION from the process
// environment, else from env (the loaded .env), else "stable".
func (c *Compose) ImageTag(env map[string]string) string {
	if v := c.readVersion(); v != "" {
		return imageTag(v)
	}
	if v := strings.TrimSpace(os.Getenv("BUGGY_VERSION")); v != "" {
		return v
	}
	if v := strings.TrimSpace(env["BUGGY_VERSION"]); v != "" {
		return v
	}
	return "stable"
}

// DefaultImagePrefix is the registry prefix an installed launcher's images
// are pulled from when neither the process environment nor .env sets
// BUGGY_IMAGE_PREFIX. Release builds set it (cmd/root.go) to
// project.ImagePrefix(); development builds leave it empty, so compose
// resolves the bare local names a source build tags (`buggy-<name>:<tag>`).
var DefaultImagePrefix = ""

// ImagePrefix returns what compose resolves ${BUGGY_IMAGE_PREFIX:-} to for
// this install: the process environment when it sets the variable (even to
// empty), else env (the loaded .env) when it has the key, else
// DefaultImagePrefix.
func ImagePrefix(env map[string]string) string {
	if v, ok := os.LookupEnv(project.ImagePrefixEnv); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := env[project.ImagePrefixEnv]; ok {
		return strings.TrimSpace(v)
	}
	return DefaultImagePrefix
}

// imagePrefixEnv returns the BUGGY_IMAGE_PREFIX entry to add to a compose
// child's environment: DefaultImagePrefix, but only when neither the
// process environment nor the stack's .env sets the variable, so an
// operator's own value (including an explicit empty one) always wins.
func (c *Compose) imagePrefixEnv() []string {
	if DefaultImagePrefix == "" {
		return nil
	}
	if _, ok := os.LookupEnv(project.ImagePrefixEnv); ok {
		return nil
	}
	if dotenv, err := config.LoadEnv(c.EnvFile); err == nil {
		if _, ok := dotenv[project.ImagePrefixEnv]; ok {
			return nil
		}
	}
	return []string{project.ImagePrefixEnv + "=" + DefaultImagePrefix}
}

// Ps shows service status.
func (c *Compose) Ps() error {
	return c.run([]string{"ps"}, false)
}

// Logs follows service logs.
func (c *Compose) Logs(service string) error {
	args := []string{"logs", "-f"}
	if service != "" {
		args = append(args, service)
	}
	return c.run(args, false)
}

// Exec runs a command inside a running service container.
func (c *Compose) Exec(service string, command ...string) error {
	return c.run(execArgs(service, command), false)
}

// ExecArgs returns the full argv (after the runtime binary) that Exec
// executes.
func (c *Compose) ExecArgs(service string, command ...string) []string {
	return append(c.baseArgs(), execArgs(service, command)...)
}

func execArgs(service string, command []string) []string {
	return append([]string{"exec", "-T", service}, command...)
}

// ExecWithEnv runs a command inside a running service container with extra
// environment variables, streaming stdout/stderr. TTY allocation is disabled
// (-T) so it works from non-interactive contexts; the invoked command must
// not require an attached stdin.
func (c *Compose) ExecWithEnv(service string, env map[string]string, command ...string) error {
	args := []string{"exec", "-T"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, service)
	args = append(args, command...)
	return c.run(args, false)
}

// RunInteractive runs a one-off container with stdin attached.
func (c *Compose) RunInteractive(profiles []string, service string, env map[string]string, command ...string) error {
	cmd := exec.Command(c.Runtime.Bin, c.RunArgs(profiles, service, env, command...)...)
	cmd.Env = c.composeEnv()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s compose run %s: %w", c.Runtime.Name, service, err)
	}
	return nil
}

// RunCaptured runs a one-off container without a terminal and returns what it
// wrote to stdout and its exit code. Stderr (image pulls, container
// lifecycle lines) goes to the launcher's stderr, so stdout stays exactly the
// command's own output. A command that could not be started returns an error.
func (c *Compose) RunCaptured(profiles []string, service string, env map[string]string, command ...string) (string, int, error) {
	cmd := exec.Command(c.Runtime.Bin, c.RunCapturedArgs(profiles, service, env, command...)...)
	cmd.Env = c.composeEnv()
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String(), exit.ExitCode(), nil
	}
	return stdout.String(), -1, fmt.Errorf("%s compose run %s: %w", c.Runtime.Name, service, err)
}

// RunCapturedArgs is RunArgs with -T (no terminal) after `run --rm`.
func (c *Compose) RunCapturedArgs(profiles []string, service string, env map[string]string, command ...string) []string {
	args := c.RunArgs(profiles, service, env, command...)
	out := make([]string, 0, len(args)+1)
	for i, arg := range args {
		out = append(out, arg)
		if arg == "--rm" && i > 0 && args[i-1] == "run" {
			out = append(out, "-T")
		}
	}
	return out
}

// RunArgs returns the full argv (after the runtime binary) that
// RunInteractive executes. The -e entries are sorted by name so the argv is
// the same on every call.
func (c *Compose) RunArgs(profiles []string, service string, env map[string]string, command ...string) []string {
	cmdArgs := c.baseArgs()
	for _, p := range profiles {
		cmdArgs = append(cmdArgs, "--profile", p)
	}
	// Note: --no-build is intentionally absent. `docker compose run` does
	// not accept --no-build (only `up` does); passing it raises
	// "unknown flag: --no-build" on every Compose version. The original
	// concern (OSS users without source triggering a build) doesn't
	// apply here because the cli image is pulled at install time and
	// `run` only builds when the image is missing.
	cmdArgs = append(cmdArgs, "run", "--rm")
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		cmdArgs = append(cmdArgs, "-e", k+"="+env[k])
	}
	cmdArgs = append(cmdArgs, service)
	return append(cmdArgs, command...)
}

// CleanScratch removes legacy root-level scratch/session directories inside
// the running sandbox. Current bash tooling writes these directories under
// each engagement workspace; this cleanup only retires leftovers from older
// versions.
func (c *Compose) CleanScratch() {
	cmd := exec.Command(
		c.Runtime.Bin,
		"exec",
		ContainerName("sandbox"),
		"rm",
		"-rf",
		"/workspace/.scratch",
		"/workspace/.sessions",
	)
	cmd.Env = c.composeEnv()
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}

// RemoveOrphanedCLI removes any leftover CLI containers.
func (c *Compose) RemoveOrphanedCLI() {
	// Best-effort cleanup of orphaned CLI containers.
	// Anchor the filter to the stack naming convention used by ContainerName
	// so we don't accidentally match unrelated containers. Use the detected
	// runtime binary (docker / podman / nerdctl) and its env.
	stack := strings.TrimSpace(os.Getenv("BUGGY_STACK_NAME"))
	prefix := "buggy"
	if stack != "" {
		prefix = "buggy-" + stack
	}
	ps := exec.Command(c.Runtime.Bin, "ps", "-aq", "--filter", fmt.Sprintf("name=^%s-cli", prefix))
	ps.Env = c.composeEnv()
	out, err := ps.Output()
	if err != nil || len(out) == 0 {
		return
	}
	ids := strings.Fields(strings.TrimSpace(string(out)))
	for _, id := range ids {
		rm := exec.Command(c.Runtime.Bin, "rm", "-f", id)
		rm.Env = c.composeEnv()
		_ = rm.Run()
	}
}

// Env is the environment every compose call of this stack runs with. It is
// exported for a caller that has to hand the same compose command to another
// program (the Claude Code agent stage starts the bridge through it).
func (c *Compose) Env() []string {
	return c.composeEnv()
}
