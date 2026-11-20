package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/spf13/cobra"
)

var (
	doctorProfile string
	doctorJSON    bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the prerequisites of `buggy hunt` and print a fix for each one that fails",
	Long: "Checks Docker on this machine (the docker command, Compose v2, the " +
		"daemon). When they pass and the stack's image is present, the full " +
		"preflight (`buggy-cli doctor`) runs in the operator container; " +
		"otherwise the Docker checks are printed with the fix for each.\n\n" +
		"  buggy doctor\n" +
		"  buggy doctor --profile lite\n" +
		"  buggy doctor --json",
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().StringVar(&doctorProfile, "profile", doctorProfileFull, "lite: recon pipeline only; full: the whole stack with agents")
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, `Print {"ok": bool, "checks": [...]} instead of a table`)
	rootCmd.AddCommand(doctorCmd)
}

const (
	doctorProfileLite = "lite"
	doctorProfileFull = "full"

	doctorOK   = "ok"
	doctorFail = "fail"

	// The three fixes below are the wording of `buggy-cli doctor`
	// (packages/buggy/buggy/cli/doctor.py: DOCKER_FIX, COMPOSE_FIX,
	// DAEMON_FIX); a test compares them with that file.
	doctorDockerFix  = "install Docker Engine or Docker Desktop (https://docs.docker.com/get-docker/)"
	doctorComposeFix = "install the Docker Compose v2 plugin (https://docs.docker.com/compose/install/)"
	doctorDaemonFix  = "start Docker (Docker Desktop, or `sudo systemctl start docker`) and check that " +
		"`docker info` works for your user"
	doctorRerunFix  = "fix the docker checks above, then run `buggy doctor` again"
	doctorImagesFix = "run `make build-images`"
	doctorFilesFix  = "run `buggy onboard` if .env is missing; `buggy hunt --lite` and `buggy demo` download a missing compose file"

	doctorCommandTimeout = 20 * time.Second
)

// doctorCheck is one preflight result, in the shape `buggy-cli doctor` prints.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// doctorHost is the machine the checks look at. Tests pass fakes.
type doctorHost struct {
	// lookPath resolves a command on PATH.
	lookPath func(name string) (string, error)
	// run executes argv and returns its exit code and output: stdout on
	// success, the error text otherwise.
	run func(argv ...string) (int, string)
	// exists reports whether a file is on disk.
	exists func(path string) bool
}

// doctorHostFn is indirected so tests can run the command on a described
// machine instead of this one.
var doctorHostFn = realDoctorHost

func realDoctorHost() doctorHost {
	return doctorHost{
		lookPath: exec.LookPath,
		run:      runDoctorCommand,
		exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
	}
}

func runDoctorCommand(argv ...string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), doctorCommandTimeout)
	defer cancel()
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out, errText := strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String())
	if err == nil {
		return 0, out
	}
	if ctx.Err() == context.DeadlineExceeded {
		return 124, fmt.Sprintf("timed out after %.0fs", doctorCommandTimeout.Seconds())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 127, err.Error()
	}
	if errText == "" {
		errText = out
	}
	return exit.ExitCode(), errText
}

var doctorComposeVersion = regexp.MustCompile(`\bv?(\d+)\.(\d+)(?:\.(\d+))?`)

func doctorFirstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(line)
}

func doctorOr(line string, code int) string {
	if line != "" {
		return line
	}
	return "exit " + strconv.Itoa(code)
}

func checkDoctorDocker(host doctorHost) doctorCheck {
	if path, err := host.lookPath("docker"); err == nil && path != "" {
		return doctorCheck{"docker", doctorOK, path, ""}
	}
	return doctorCheck{"docker", doctorFail, "the `docker` command is not on PATH", doctorDockerFix}
}

func checkDoctorCompose(host doctorHost) doctorCheck {
	const name = "docker compose"
	code, output := host.run("docker", "compose", "version")
	line := doctorFirstLine(output)
	if code != 0 {
		return doctorCheck{name, doctorFail, "`docker compose version` failed: " + doctorOr(line, code), doctorComposeFix}
	}
	match := doctorComposeVersion.FindStringSubmatch(output)
	if match == nil {
		if line == "" {
			line = "(no output)"
		}
		return doctorCheck{name, doctorFail, "cannot read a version from `docker compose version`: " + line, doctorComposeFix}
	}
	version := match[1] + "." + match[2]
	if match[3] != "" {
		version += "." + match[3]
	}
	if major, err := strconv.Atoi(match[1]); err != nil || major < 2 {
		return doctorCheck{name, doctorFail, "Compose v" + version + " found; v2 or newer is required", doctorComposeFix}
	}
	return doctorCheck{name, doctorOK, "v" + version, ""}
}

func checkDoctorDaemon(host doctorHost) doctorCheck {
	const name = "docker daemon"
	code, output := host.run("docker", "info", "--format", "{{.ServerVersion}}")
	line := doctorFirstLine(output)
	if code == 0 && line != "" {
		return doctorCheck{name, doctorOK, "server " + line, ""}
	}
	return doctorCheck{name, doctorFail, "the Docker daemon is not reachable: " + doctorOr(line, code), doctorDaemonFix}
}

func checkDoctorImage(host doctorHost, image string) doctorCheck {
	name := "image " + image
	code, output := host.run("docker", "image", "inspect", "--format", "{{.Id}}", image)
	if code == 0 {
		return doctorCheck{name, doctorOK, "present", ""}
	}
	return doctorCheck{name, doctorFail, "not found locally (" + doctorOr(doctorFirstLine(output), code) + ")", doctorImagesFix}
}

func checkDoctorFiles(host doctorHost, files []string) doctorCheck {
	const name = "stack files"
	var missing []string
	for _, file := range files {
		if !host.exists(file) {
			missing = append(missing, file)
		}
	}
	if len(missing) == 0 {
		return doctorCheck{name, doctorOK, "present", ""}
	}
	return doctorCheck{name, doctorFail, "missing: " + strings.Join(missing, ", "), doctorFilesFix}
}

// doctorNotChecked never reports an unverified prerequisite as passing.
func doctorNotChecked(name, why string) doctorCheck {
	return doctorCheck{name, doctorFail, "not checked: " + why, doctorRerunFix}
}

// doctorHostChecks runs the three host checks: the docker command, Compose
// v2, the daemon. They are always three, in that order; when docker itself
// is missing the other two are reported as not checked.
func doctorHostChecks(host doctorHost) []doctorCheck {
	docker := checkDoctorDocker(host)
	if docker.Status != doctorOK {
		const why = "docker is not installed"
		return []doctorCheck{docker, doctorNotChecked("docker compose", why), doctorNotChecked("docker daemon", why)}
	}
	return []doctorCheck{docker, checkDoctorCompose(host), checkDoctorDaemon(host)}
}

// doctorPreflight decides whether the full preflight can run in the operator
// container. It can when the three host checks pass, the operator's image is
// present and the stack's files are on disk. Otherwise the checks to print
// are returned: the three host checks, then (only when Docker works, so the
// answer means something) the image and the files.
func doctorPreflight(host doctorHost, image string, files []string) (checks []doctorCheck, inContainer bool) {
	checks = doctorHostChecks(host)
	if !doctorPassed(checks) {
		return checks, false
	}
	checks = append(checks, checkDoctorImage(host, image), checkDoctorFiles(host, files))
	return checks, doctorPassed(checks)
}

func doctorPassed(checks []doctorCheck) bool {
	for _, check := range checks {
		if check.Status == doctorFail {
			return false
		}
	}
	return true
}

// renderDoctorJSON matches `buggy-cli doctor --json`.
func renderDoctorJSON(checks []doctorCheck) string {
	out, err := json.MarshalIndent(struct {
		OK     bool          `json:"ok"`
		Checks []doctorCheck `json:"checks"`
	}{doctorPassed(checks), checks}, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(out)
}

// renderDoctorTable matches the table of `buggy-cli doctor`: one line per
// check (status, name, detail, then the fix when there is one) and a verdict.
func renderDoctorTable(checks []doctorCheck) string {
	labels := map[string]string{doctorOK: "ok", doctorFail: "FAIL"}
	nameWidth := 0
	for _, check := range checks {
		nameWidth = max(nameWidth, len(check.Name))
	}
	var lines []string
	failed := 0
	for _, check := range checks {
		if check.Status == doctorFail {
			failed++
		}
		line := fmt.Sprintf("%-4s  %-*s  %s", labels[check.Status], nameWidth, check.Name, check.Detail)
		if check.Fix != "" {
			line += "  fix: " + check.Fix
		}
		lines = append(lines, strings.TrimRight(line, " "))
	}
	verdict := "ready"
	if failed > 0 {
		verdict = "not ready"
	}
	lines = append(lines, "", fmt.Sprintf("%s: %d ok, 0 warn, %d failed", verdict, len(checks)-failed, failed))
	return strings.Join(lines, "\n")
}

// doctorCompose returns the stack whose operator runs the preflight.
func doctorCompose(profile string) *compose.Compose {
	return huntCompose(profile == doctorProfileLite)
}

// doctorOperatorImage is the image of the operator service of the profile's
// stack: the slim pipeline image in the lite file, the agent image in the
// full one.
func doctorOperatorImage(profile, tag string) string {
	if profile == doctorProfileLite {
		return "buggy-pipeline:" + tag
	}
	return "buggy-langgraph:" + tag
}

// doctorOperatorCommand is the preflight command for the operator container.
// The lite operator is the slim pipeline image, which has no `buggy-cli`
// script, so there the command runs as a module.
func doctorOperatorCommand(profile string, asJSON bool) []string {
	command := []string{"buggy-cli", "doctor"}
	if profile == doctorProfileLite {
		command = []string{"python", "-m", "buggy.cli", "doctor"}
	}
	command = append(command, "--profile", profile)
	if asJSON {
		command = append(command, "--json")
	}
	return command
}

func runDoctor(cmd *cobra.Command, args []string) error {
	if doctorProfile != doctorProfileLite && doctorProfile != doctorProfileFull {
		return fmt.Errorf("unknown profile %q (expected one of %s, %s)", doctorProfile, doctorProfileLite, doctorProfileFull)
	}
	// A missing .env is not an error here: it is one of the things reported.
	env, _ := config.LoadEnv(config.EnvPath())

	c := doctorCompose(doctorProfile)
	image := doctorOperatorImage(doctorProfile, c.ImageTag(env))
	files := append(c.Files(), c.EnvFile)
	checks, inContainer := doctorPreflight(doctorHostFn(), image, files)
	if inContainer {
		err := c.RunInteractive([]string{compose.Profiles.Operator}, "operator", nil,
			doctorOperatorCommand(doctorProfile, doctorJSON)...)
		// The preflight printed its own report. Pass its verdict on as the
		// exit code; an error line on stdout would break --json.
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			doctorExit(exit.ExitCode())
			return nil
		}
		return err
	}

	fmt.Println(renderDoctorReport(checks, doctorJSON))
	doctorExit(doctorExitFailed)
	return nil
}

// doctorExitFailed is the exit code of `buggy-cli doctor` when a required
// check fails.
const doctorExitFailed = 2

// doctorExit ends the process with the preflight's verdict. It is a variable
// so tests can observe the code.
var doctorExit = os.Exit

// renderDoctorReport is everything doctor writes to stdout for checks.
func renderDoctorReport(checks []doctorCheck, asJSON bool) string {
	if asJSON {
		return renderDoctorJSON(checks)
	}
	return renderDoctorTable(checks)
}
