package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
)

type doctorReply struct {
	code   int
	output string
}

// fakeDoctorHost is a machine described by data: whether docker is on PATH,
// what each docker command answers, which files exist. It records every
// command it was asked to run.
type fakeDoctorHost struct {
	dockerPath string
	replies    map[string]doctorReply
	missing    []string
	calls      []string
}

func (f *fakeDoctorHost) host() doctorHost {
	return doctorHost{
		lookPath: func(name string) (string, error) {
			if name == "docker" && f.dockerPath != "" {
				return f.dockerPath, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		run: func(argv ...string) (int, string) {
			key := strings.Join(argv, " ")
			f.calls = append(f.calls, key)
			reply, ok := f.replies[key]
			if !ok {
				return 127, "unexpected command: " + key
			}
			return reply.code, reply.output
		},
		exists: func(path string) bool { return !slices.Contains(f.missing, path) },
	}
}

const (
	composeVersionCmd = "docker compose version"
	daemonInfoCmd     = "docker info --format {{.ServerVersion}}"
	testImage         = "buggy-pipeline:stable"
	imageInspectCmd   = "docker image inspect --format {{.Id}} " + testImage
)

// healthyHost is a machine on which every check passes.
func healthyHost() *fakeDoctorHost {
	return &fakeDoctorHost{
		dockerPath: "/usr/bin/docker",
		replies: map[string]doctorReply{
			composeVersionCmd: {0, "Docker Compose version v2.29.7"},
			daemonInfoCmd:     {0, "27.3.1"},
			imageInspectCmd:   {0, "sha256:0000"},
		},
	}
}

var testFiles = []string{"/home/docker-compose.lite.yml", "/home/.env"}

func checkNamed(t *testing.T, checks []doctorCheck, name string) doctorCheck {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("no check named %q in %+v", name, checks)
	return doctorCheck{}
}

func TestDoctorPreflight_HealthyHostRunsInTheContainer(t *testing.T) {
	fake := healthyHost()
	checks, inContainer := doctorPreflight(fake.host(), testImage, testFiles)
	if !inContainer {
		t.Fatalf("healthy host: inContainer = false; checks = %+v", checks)
	}
	for _, check := range checks {
		if check.Status != doctorOK || check.Fix != "" {
			t.Errorf("healthy host: %+v", check)
		}
	}
	if got := checkNamed(t, checks, "docker compose").Detail; got != "v2.29.7" {
		t.Errorf("compose detail = %q", got)
	}
	if got := checkNamed(t, checks, "docker daemon").Detail; got != "server 27.3.1" {
		t.Errorf("daemon detail = %q", got)
	}
}

func TestDoctorPreflight_MissingDockerPrintsThreeHostChecks(t *testing.T) {
	fake := healthyHost()
	fake.dockerPath = ""
	checks, inContainer := doctorPreflight(fake.host(), testImage, testFiles)
	if inContainer {
		t.Fatal("docker is not installed, yet the preflight would run a container")
	}
	want := []doctorCheck{
		{"docker", doctorFail, "the `docker` command is not on PATH", doctorDockerFix},
		{"docker compose", doctorFail, "not checked: docker is not installed", doctorRerunFix},
		{"docker daemon", doctorFail, "not checked: docker is not installed", doctorRerunFix},
	}
	if !reflect.DeepEqual(checks, want) {
		t.Errorf("checks:\n got %+v\nwant %+v", checks, want)
	}
	if len(fake.calls) != 0 {
		t.Errorf("docker is not on PATH, yet it was run: %v", fake.calls)
	}
}

func TestDoctorPreflight_FailuresCarryTheFix(t *testing.T) {
	cases := []struct {
		name       string
		break_     func(*fakeDoctorHost)
		check      string
		wantDetail string
		wantFix    string
	}{
		{
			name: "compose plugin missing",
			break_: func(f *fakeDoctorHost) {
				f.replies[composeVersionCmd] = doctorReply{1, "docker: 'compose' is not a docker command.\nSee 'docker --help'"}
			},
			check:      "docker compose",
			wantDetail: "`docker compose version` failed: docker: 'compose' is not a docker command.",
			wantFix:    doctorComposeFix,
		},
		{
			name: "compose v1",
			break_: func(f *fakeDoctorHost) {
				f.replies[composeVersionCmd] = doctorReply{0, "docker-compose version 1.29.2, build 5becea4c"}
			},
			check:      "docker compose",
			wantDetail: "Compose v1.29.2 found; v2 or newer is required",
			wantFix:    doctorComposeFix,
		},
		{
			name:       "compose prints no version",
			break_:     func(f *fakeDoctorHost) { f.replies[composeVersionCmd] = doctorReply{0, ""} },
			check:      "docker compose",
			wantDetail: "cannot read a version from `docker compose version`: (no output)",
			wantFix:    doctorComposeFix,
		},
		{
			name: "daemon down",
			break_: func(f *fakeDoctorHost) {
				f.replies[daemonInfoCmd] = doctorReply{1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."}
			},
			check:      "docker daemon",
			wantDetail: "the Docker daemon is not reachable: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
			wantFix:    doctorDaemonFix,
		},
		{
			name:       "daemon answers nothing",
			break_:     func(f *fakeDoctorHost) { f.replies[daemonInfoCmd] = doctorReply{0, ""} },
			check:      "docker daemon",
			wantDetail: "the Docker daemon is not reachable: exit 0",
			wantFix:    doctorDaemonFix,
		},
		{
			name: "image not built",
			break_: func(f *fakeDoctorHost) {
				f.replies[imageInspectCmd] = doctorReply{1, "Error response from daemon: No such image: " + testImage}
			},
			check:      "image " + testImage,
			wantDetail: "not found locally (Error response from daemon: No such image: " + testImage + ")",
			wantFix:    doctorImagesFix,
		},
		{
			name:       "compose file missing",
			break_:     func(f *fakeDoctorHost) { f.missing = []string{testFiles[0]} },
			check:      "stack files",
			wantDetail: "missing: " + testFiles[0],
			wantFix:    doctorFilesFix,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := healthyHost()
			tc.break_(fake)
			checks, inContainer := doctorPreflight(fake.host(), testImage, testFiles)
			if inContainer {
				t.Fatal("a failed check must keep the preflight out of the container")
			}
			got := checkNamed(t, checks, tc.check)
			want := doctorCheck{tc.check, doctorFail, tc.wantDetail, tc.wantFix}
			if got != want {
				t.Errorf("check:\n got %+v\nwant %+v", got, want)
			}
			// The three host checks are always reported, in order.
			names := []string{checks[0].Name, checks[1].Name, checks[2].Name}
			if !reflect.DeepEqual(names, []string{"docker", "docker compose", "docker daemon"}) {
				t.Errorf("host checks = %v", names)
			}
			// Every other check passed: one defect, one failure.
			for _, check := range checks {
				if check.Name != tc.check && check.Status != doctorOK {
					t.Errorf("unrelated check failed: %+v", check)
				}
			}
		})
	}
}

// With no daemon, "image not found" would be a guess: it is not asked.
func TestDoctorPreflight_ImageIsNotInspectedWithoutADaemon(t *testing.T) {
	fake := healthyHost()
	fake.replies[daemonInfoCmd] = doctorReply{1, "Cannot connect to the Docker daemon"}
	checks, _ := doctorPreflight(fake.host(), testImage, testFiles)
	if len(checks) != 3 {
		t.Errorf("checks = %+v, want exactly the three host checks", checks)
	}
	if slices.Contains(fake.calls, imageInspectCmd) {
		t.Errorf("image inspected although the daemon is down: %v", fake.calls)
	}
	// Control: on a healthy host the image is inspected.
	healthy := healthyHost()
	doctorPreflight(healthy.host(), testImage, testFiles)
	if !slices.Contains(healthy.calls, imageInspectCmd) {
		t.Errorf("healthy host: image was not inspected: %v", healthy.calls)
	}
}

func TestDoctorOperatorArgv(t *testing.T) {
	home := stackHome(t)
	cases := []struct {
		profile string
		file    string
		image   string
		command []string
	}{
		{"lite", "docker-compose.lite.yml", "buggy-pipeline:1.2.3", []string{"python", "-m", "buggy.cli", "doctor", "--profile", "lite", "--in-container", "--json"}},
		{"full", "docker-compose.yml", "buggy-langgraph:1.2.3", []string{"buggy-cli", "doctor", "--profile", "full", "--in-container", "--json"}},
	}
	for _, tc := range cases {
		// -T: the report is captured, so no terminal is attached.
		want := append([]string{
			"compose", "-p", "buggy",
			"-f", filepath.Join(home, tc.file),
			"--env-file", filepath.Join(home, ".env"),
			"--profile", "operator", "run", "--rm", "-T", "operator",
		}, tc.command...)
		got := dockerShaped(doctorCompose(tc.profile)).RunCapturedArgs(
			[]string{compose.Profiles.Operator}, "operator", nil,
			doctorOperatorCommand(tc.profile)...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s argv:\n got %v\nwant %v", tc.profile, got, want)
		}
		if got := doctorOperatorImage(tc.profile, "", "1.2.3"); got != tc.image {
			t.Errorf("%s image = %q, want %q", tc.profile, got, tc.image)
		}
		if got, want := doctorOperatorImage(tc.profile, "ghcr.io/owner/", "1.2.3"), "ghcr.io/owner/"+tc.image; got != want {
			t.Errorf("%s prefixed image = %q, want %q", tc.profile, got, want)
		}
	}
}

// containerSays makes the container half answer with stdout and an exit code.
func containerSays(t *testing.T, stdout string, code int, err error) *int {
	t.Helper()
	prev := doctorContainerFn
	t.Cleanup(func() { doctorContainerFn = prev })
	calls := 0
	doctorContainerFn = func(*compose.Compose, string) (string, int, error) {
		calls++
		return stdout, code, err
	}
	return &calls
}

const containerReport = `{"ok": true, "checks": [
  {"name": "secret BUGGY_STACK_MCP_TOKEN", "status": "ok", "detail": "set", "fix": ""},
  {"name": "mounts", "status": "ok", "detail": "mounted", "fix": ""},
  {"name": "model", "status": "warn", "detail": "no model configured", "fix": "set a key"}]}`

// On a healthy host the report is the host's checks followed by the
// container's, and a warning does not fail it.
func TestRunDoctor_HealthyHostMergesTheContainerChecks(t *testing.T) {
	stackHome(t)
	calls := containerSays(t, containerReport, 0, nil)
	out, code, err := runDoctorOn(t, healthyHost(), "lite", true)
	if err != nil || code != -1 {
		t.Fatalf("err=%v exit=%d, want nil and no exit", err, code)
	}
	var report struct {
		OK     bool          `json:"ok"`
		Checks []doctorCheck `json:"checks"`
	}
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", jsonErr, out)
	}
	var names []string
	for _, check := range report.Checks {
		names = append(names, check.Name)
	}
	want := []string{"docker", "docker compose", "docker daemon", "image buggy-pipeline:stable", "stack files",
		"secret BUGGY_STACK_MCP_TOKEN", "mounts", "model"}
	if !report.OK || !reflect.DeepEqual(names, want) || *calls != 1 {
		t.Errorf("ok=%v calls=%d names=%v", report.OK, *calls, names)
	}

	table, code, err := runDoctorOn(t, healthyHost(), "lite", false)
	if err != nil || code != -1 || !strings.Contains(table, "ready: 7 ok, 1 warn, 0 failed") ||
		!strings.Contains(table, "warn  model") {
		t.Errorf("table run: err=%v exit=%d\n%s", err, code, table)
	}
}

// A failed check inside the container fails the whole preflight.
func TestRunDoctor_AContainerFailureExitsTwo(t *testing.T) {
	stackHome(t)
	containerSays(t, strings.Replace(containerReport, `"mounts", "status": "ok"`, `"mounts", "status": "fail"`, 1), 2, nil)
	out, code, err := runDoctorOn(t, healthyHost(), "lite", false)
	if err != nil || code != 2 || !strings.Contains(out, "FAIL  mounts") {
		t.Errorf("err=%v exit=%d\n%s", err, code, out)
	}
}

// A container that prints no report is a failure, never a pass.
func TestRunDoctor_NoReportFromTheContainerIsAFailure(t *testing.T) {
	stackHome(t)
	for _, tc := range []struct {
		stdout string
		err    error
		want   string
	}{
		{"Traceback (most recent call last):", nil, "no report from the container (exit 1): Traceback"},
		{"", nil, "no report from the container (exit 1)"},
		{`{"ok": true, "checks": []}`, nil, "no report from the container"},
		{"", errors.New("exec: docker not found"), "could not be started: exec: docker not found"},
	} {
		containerSays(t, tc.stdout, 1, tc.err)
		out, code, err := runDoctorOn(t, healthyHost(), "lite", false)
		if err != nil || code != 2 || !strings.Contains(out, "FAIL  operator container") || !strings.Contains(out, tc.want) {
			t.Errorf("%q: err=%v exit=%d\n%s", tc.stdout, err, code, out)
		}
	}
}

// The container is not started when the host half already failed.
func TestRunDoctor_ContainerIsNotRunOnABrokenHost(t *testing.T) {
	stackHome(t)
	calls := containerSays(t, containerReport, 0, nil)
	fake := healthyHost()
	fake.dockerPath = ""
	if _, code, _ := runDoctorOn(t, fake, "lite", false); code != 2 || *calls != 0 {
		t.Errorf("exit=%d container calls=%d, want 2 and 0", code, *calls)
	}
}

// The image the launcher looks for must be the image the operator service of
// that stack really runs, as the compose files in the repository define it.
func TestDoctorOperatorImage_MatchesTheComposeFiles(t *testing.T) {
	operatorImage := regexp.MustCompile(`(?m)^  operator:\n(?:(?:    .*)?\n)*?    image: (\S+)`)
	for profile, file := range map[string]string{"lite": compose.LiteFile, "full": compose.MainFile} {
		source, err := os.ReadFile(filepath.Join("..", "..", "..", file))
		if err != nil {
			t.Skip("compose files not found next to the launcher module")
		}
		match := operatorImage.FindSubmatch(source)
		if match == nil {
			t.Fatalf("%s: no operator image found", file)
		}
		declared := string(match[1])
		if !strings.HasSuffix(declared, ":${BUGGY_VERSION:-stable}") {
			t.Fatalf("%s: operator image %q is not tagged ${BUGGY_VERSION:-stable}", file, declared)
		}
		if !strings.HasPrefix(declared, "${BUGGY_IMAGE_PREFIX:-}") {
			t.Fatalf("%s: operator image %q has no ${BUGGY_IMAGE_PREFIX:-} prefix", file, declared)
		}
		for _, prefix := range []string{"", "ghcr.io/owner/"} {
			want := strings.NewReplacer(
				"${BUGGY_IMAGE_PREFIX:-}", prefix,
				"${BUGGY_VERSION:-stable}", "9.9.9",
			).Replace(declared)
			if got := doctorOperatorImage(profile, prefix, "9.9.9"); got != want {
				t.Errorf("%s: doctor looks for %q, the operator runs %q", profile, got, want)
			}
		}
	}
}

func TestDoctorFlags(t *testing.T) {
	profile := doctorCmd.Flags().Lookup("profile")
	if profile == nil || profile.DefValue != "full" {
		t.Fatalf("--profile = %+v, want default full (as buggy-cli doctor)", profile)
	}
	if doctorCmd.Flags().Lookup("json") == nil {
		t.Fatal("doctor has no --json flag")
	}

	prev := doctorProfile
	t.Cleanup(func() { doctorProfile = prev })
	doctorProfile = "everything"
	err := runDoctor(doctorCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown profile "everything"`) {
		t.Errorf("unknown profile: err = %v", err)
	}
}

// runDoctorOn runs the doctor command on a described machine and returns
// what it wrote to stdout, the exit code it asked for (-1: none) and its error.
func runDoctorOn(t *testing.T, fake *fakeDoctorHost, profile string, asJSON bool) (string, int, error) {
	t.Helper()
	prevHost, prevExit, prevProfile, prevJSON, prevStdout := doctorHostFn, doctorExit, doctorProfile, doctorJSON, os.Stdout
	t.Cleanup(func() {
		doctorHostFn, doctorExit, doctorProfile, doctorJSON, os.Stdout = prevHost, prevExit, prevProfile, prevJSON, prevStdout
	})
	code := -1
	doctorHostFn = fake.host
	doctorExit = func(c int) { code = c }
	doctorProfile, doctorJSON = profile, asJSON

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	runErr := runDoctor(doctorCmd, nil)
	os.Stdout = prevStdout
	write.Close()
	out := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, readErr := read.Read(buf)
		out.Write(buf[:n])
		if readErr != nil {
			break
		}
	}
	return out.String(), code, runErr
}

// A failed preflight exits 2 like `buggy-cli doctor`, and with --json stdout
// is the report and nothing else, so it can be piped into a JSON parser.
func TestRunDoctor_FailedHostChecksExitTwoAndKeepStdoutClean(t *testing.T) {
	stackHome(t)
	fake := healthyHost()
	fake.dockerPath = ""

	out, code, err := runDoctorOn(t, fake, "lite", true)
	if err != nil || code != 2 {
		t.Fatalf("err=%v exit=%d, want nil and 2", err, code)
	}
	var report struct {
		OK     bool          `json:"ok"`
		Checks []doctorCheck `json:"checks"`
	}
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", jsonErr, out)
	}
	if report.OK || len(report.Checks) != 3 || report.Checks[0].Fix != doctorDockerFix {
		t.Errorf("report = %+v", report)
	}

	table, code, err := runDoctorOn(t, fake, "full", false)
	if err != nil || code != 2 || !strings.Contains(table, "not ready: 0 ok, 0 warn, 3 failed") {
		t.Errorf("table run: err=%v exit=%d\n%s", err, code, table)
	}
	if len(fake.calls) != 0 {
		t.Errorf("docker is not on PATH, yet it was run: %v", fake.calls)
	}
}

// The image the command looks for is the profile's operator image at the
// install's tag, and a missing image keeps it out of the container.
func TestRunDoctor_MissingImageIsReportedByName(t *testing.T) {
	home := stackHome(t)
	t.Setenv("BUGGY_VERSION", "")
	if err := os.WriteFile(filepath.Join(home, ".version"), []byte("v4.5.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := healthyHost() // knows buggy-pipeline:stable only
	fake.missing = []string{filepath.Join(home, "docker-compose.lite.yml")}
	out, code, err := runDoctorOn(t, fake, "lite", false)
	if err != nil || code != 2 {
		t.Fatalf("err=%v exit=%d, want nil and 2", err, code)
	}
	if !slices.Contains(fake.calls, "docker image inspect --format {{.Id}} buggy-pipeline:4.5.6") {
		t.Errorf("inspected the wrong image: %v", fake.calls)
	}
	if !strings.Contains(out, "FAIL  image buggy-pipeline:4.5.6") || !strings.Contains(out, "fix: "+doctorImagesFix) {
		t.Errorf("missing image not reported:\n%s", out)
	}
	// The files it asks about are the lite stack's, in this Buggy home.
	if !strings.Contains(out, "missing: "+filepath.Join(home, "docker-compose.lite.yml")+"  fix:") {
		t.Errorf("missing stack file not reported:\n%s", out)
	}
}

// An install whose .env names a registry prefix is checked for the
// prefixed image, the one compose pulls and runs.
func TestRunDoctor_HonoursTheImagePrefix(t *testing.T) {
	home := stackHome(t)
	t.Setenv("BUGGY_VERSION", "")
	if err := os.WriteFile(filepath.Join(home, ".version"), []byte("v4.5.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUGGY_IMAGE_PREFIX", "ghcr.io/owner/")
	fake := healthyHost()
	_, _, _ = runDoctorOn(t, fake, "lite", false)
	if !slices.Contains(fake.calls, "docker image inspect --format {{.Id}} ghcr.io/owner/buggy-pipeline:4.5.6") {
		t.Errorf("inspected the wrong image: %v", fake.calls)
	}
}

func TestRenderDoctorTable(t *testing.T) {
	fake := healthyHost()
	fake.replies[daemonInfoCmd] = doctorReply{1, "Cannot connect to the Docker daemon"}
	checks := doctorHostChecks(fake.host())
	want := strings.Join([]string{
		"ok    docker          /usr/bin/docker",
		"ok    docker compose  v2.29.7",
		"FAIL  docker daemon   the Docker daemon is not reachable: Cannot connect to the Docker daemon  fix: " + doctorDaemonFix,
		"",
		"not ready: 2 ok, 0 warn, 1 failed",
	}, "\n")
	if got := renderDoctorTable(checks); got != want {
		t.Errorf("table:\n%s\nwant:\n%s", got, want)
	}

	ready := renderDoctorTable(doctorHostChecks(healthyHost().host()))
	if !strings.HasSuffix(ready, "\nready: 3 ok, 0 warn, 0 failed") || strings.Contains(ready, "fix:") {
		t.Errorf("healthy table:\n%s", ready)
	}
}

func TestRenderDoctorJSON(t *testing.T) {
	fake := healthyHost()
	fake.dockerPath = ""
	var report struct {
		OK     *bool               `json:"ok"`
		Checks []map[string]string `json:"checks"`
	}
	if err := json.Unmarshal([]byte(renderDoctorJSON(doctorHostChecks(fake.host()))), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK == nil || *report.OK {
		t.Errorf("ok = %v, want false", report.OK)
	}
	wantFirst := map[string]string{
		"name": "docker", "status": "fail",
		"detail": "the `docker` command is not on PATH", "fix": doctorDockerFix,
	}
	if len(report.Checks) != 3 || !reflect.DeepEqual(report.Checks[0], wantFirst) {
		t.Errorf("checks = %+v", report.Checks)
	}

	if err := json.Unmarshal([]byte(renderDoctorJSON(doctorHostChecks(healthyHost().host()))), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK == nil || !*report.OK {
		t.Errorf("healthy host: ok = %v, want true", report.OK)
	}
}

// The launcher's three host checks must read like `buggy-cli doctor`: the
// fixes are compared with the constants in the Python command.
func TestDoctorWording_MatchesThePythonDoctor(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "buggy", "buggy", "cli", "doctor.py"))
	if err != nil {
		t.Skip("doctor.py not found next to the launcher module")
	}
	// Join Python's adjacent string literals ("a " \n "b") into one.
	joined := regexp.MustCompile(`"\s*\n\s*"`).ReplaceAllString(string(source), "")
	for name, fix := range map[string]string{
		"DOCKER_FIX":  doctorDockerFix,
		"COMPOSE_FIX": doctorComposeFix,
		"DAEMON_FIX":  doctorDaemonFix,
	} {
		assigned := regexp.MustCompile(name + `\s*=\s*\(?\s*"` + regexp.QuoteMeta(fix) + `"`)
		if !assigned.MatchString(joined) {
			t.Errorf("%s in doctor.py is not %q", name, fix)
		}
	}
	for _, detail := range []string{
		"the `docker` command is not on PATH",
		"`docker compose version` failed: ",
		"; v2 or newer is required",
		"the Docker daemon is not reachable: ",
	} {
		if !strings.Contains(joined, detail) {
			t.Errorf("doctor.py no longer says %q", detail)
		}
	}
	// Control: the comparison is not vacuous.
	if regexp.MustCompile(`DOCKER_FIX\s*=\s*\(?\s*"` + regexp.QuoteMeta(doctorDaemonFix) + `"`).MatchString(joined) {
		t.Error("the wording comparison matches anything")
	}
}
