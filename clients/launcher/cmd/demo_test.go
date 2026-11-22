package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
)

// demoBase is the part every demo compose argv starts with: the project,
// then the three files in merge order.
func demoBase(home string) []string {
	return []string{
		"compose", "-p", "buggy",
		"-f", filepath.Join(home, "docker-compose.lite.yml"),
		"--env-file", filepath.Join(home, ".env"),
		"-f", filepath.Join(home, "docker-compose.lab.yml"),
		"-f", filepath.Join(home, "docker-compose.demo.yml"),
	}
}

func TestDemo_ComposeFileList(t *testing.T) {
	home := stackHome(t)
	want := []string{
		filepath.Join(home, "docker-compose.lite.yml"),
		filepath.Join(home, "docker-compose.lab.yml"),
		filepath.Join(home, "docker-compose.demo.yml"),
	}
	c := demoCompose()
	if got := c.Files(); !reflect.DeepEqual(got, want) {
		t.Errorf("demo files = %v\n      want %v", got, want)
	}
	if slices.Contains(c.Files(), filepath.Join(home, "docker-compose.yml")) {
		t.Error("the demo must not layer the full stack")
	}
}

// The files the launcher names must be the files the repository ships, or
// the demo breaks at the first run on a real install.
func TestDemo_ComposeFilesExistInTheRepository(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, compose.MainFile)); err != nil {
		t.Skip("repository root not found next to the launcher module")
	}
	stackHome(t)
	for _, file := range demoCompose().Files() {
		if _, err := os.Stat(filepath.Join(root, filepath.Base(file))); err != nil {
			t.Errorf("%s is not in the repository: %v", filepath.Base(file), err)
		}
	}
}

func TestDemo_UpArgv(t *testing.T) {
	home := stackHome(t)
	want := append(demoBase(home),
		"up", "-d", "--no-build", "--wait", "--wait-timeout", "600",
		"pipeline", "pipeline-mcp", "juice-shop")
	got := dockerShaped(demoCompose()).UpArgs(nil, demoServices...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("demo up argv:\n got %v\nwant %v", got, want)
	}
	// The lite hunt's own service list is not widened by the demo.
	if !reflect.DeepEqual(liteServices, []string{"pipeline", "pipeline-mcp"}) {
		t.Errorf("liteServices = %v", liteServices)
	}
}

func TestDemo_HuntArgv(t *testing.T) {
	home := stackHome(t)
	want := append(demoBase(home),
		"--profile", "operator", "run", "--rm", "operator",
		"python", "-m", "buggy.cli", "hunt", "http://juice-shop.lab:3000",
		"--lab", "--no-agent", "--yes", "--rps", "50", "--engagement-name", "demo")
	got := dockerShaped(demoCompose()).RunArgs(
		[]string{compose.Profiles.Operator}, "operator", nil, demoHuntCommand()...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("demo hunt argv:\n got %v\nwant %v", got, want)
	}
	// The slim operator image has no `buggy-cli` script.
	if slices.Contains(got, "buggy-cli") {
		t.Errorf("demo hunt uses buggy-cli: %v", got)
	}
}

func TestDemo_DownArgv(t *testing.T) {
	home := stackHome(t)
	want := append(demoBase(home),
		"--profile", "cli", "--profile", "operator", "down")
	got := dockerShaped(demoCompose()).DownArgs()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("demo down argv:\n got %v\nwant %v", got, want)
	}
	// The recon volumes are shared with the full stack: --down keeps them.
	for _, arg := range got {
		if arg == "--volumes" || arg == "-v" || arg == "--remove-orphans" {
			t.Errorf("demo --down passes %s", arg)
		}
	}

	flag := demoCmd.Flags().Lookup("down")
	if flag == nil || flag.DefValue != "false" {
		t.Fatalf("demo --down flag = %+v, want a flag that is off by default", flag)
	}
}

func TestDemo_WaitsForTheTargetFromThePipelineContainer(t *testing.T) {
	home := stackHome(t)
	service, command := demoWaitCommand()
	if service != "pipeline" {
		t.Errorf("wait runs in %q; only the pipeline is on the target's network", service)
	}
	if len(command) != 3 || command[0] != "python" || command[1] != "-c" {
		t.Fatalf("wait command = %v", command)
	}
	if !strings.Contains(command[2], "('juice-shop.lab', 3000)") {
		t.Errorf("wait script does not probe the hunt target:\n%s", command[2])
	}
	want := append(demoBase(home), "exec", "-T", "pipeline", "python", "-c", demoWaitScript)
	if got := dockerShaped(demoCompose()).ExecArgs(service, command...); !reflect.DeepEqual(got, want) {
		t.Errorf("demo wait argv:\n got %v\nwant %v", got, want)
	}
	// The target the script waits for is the target the hunt is given.
	if !slices.Contains(demoHuntCommand(), "http://juice-shop.lab:3000") {
		t.Errorf("hunt target differs from the waited-for target: %v", demoHuntCommand())
	}
}

func TestDemo_ReportPath(t *testing.T) {
	home := stackHome(t)
	want := filepath.Join(home, "control", "demo", "recon-report.md")
	if got := demoReportPath(); got != want {
		t.Errorf("demoReportPath = %q, want %q", got, want)
	}
	// The path is the engagement the hunt is told to write.
	command := demoHuntCommand()
	at := slices.Index(command, "--engagement-name")
	if at < 0 || command[at+1] != filepath.Base(filepath.Dir(want)) {
		t.Errorf("report path and --engagement-name disagree: %v vs %s", command, want)
	}
}
