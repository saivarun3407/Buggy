package cmd

import (
	"path/filepath"
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/spf13/cobra"
)

var demoDown bool

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Try Buggy on a bundled practice target: recon and report, no model key",
	Long: "Starts OWASP Juice Shop, an intentionally vulnerable application, on " +
		"an internal Docker network that has no route to the internet and no " +
		"published port, next to the lite stack. Then it runs a recon-only hunt " +
		"against it and prints where the report is. No model key is needed.\n\n" +
		"The demo is the lite stack with one more service, so like `buggy hunt " +
		"--lite` it cannot run side by side with the full stack from one Buggy " +
		"home.\n\n" +
		"  buggy demo\n" +
		"  buggy demo --down    (remove the demo containers and networks)",
	Args: cobra.NoArgs,
	RunE: runDemo,
}

func init() {
	demoCmd.Flags().BoolVar(&demoDown, "down", false, "Remove the demo containers and networks (reports and recon data are kept)")
	rootCmd.AddCommand(demoCmd)
}

const (
	// demoEngagement is the engagement the demo hunt writes to.
	demoEngagement = "demo"
	// demoTargetHost is the practice target's alias on the lab network.
	demoTargetHost = "juice-shop.lab"
	demoTargetPort = "3000"
	demoTarget     = "http://" + demoTargetHost + ":" + demoTargetPort
	demoTargetName = "juice-shop"
)

// demoServices are the long-running services of the demo: the lite stack and
// the practice target. The operator is a one-off container.
var demoServices = append(append([]string{}, liteServices...), demoTargetName)

// demoCompose returns the demo stack: the lite file, the lab overlay that
// defines the practice targets and their internal network, and the demo
// overlay that makes the two a runnable stack. The order is the merge order.
func demoCompose() *compose.Compose {
	return compose.NewWithFile(compose.LiteFile, compose.LabFile, compose.DemoFile)
}

// demoHuntCommand is the recon-only hunt the demo runs in the operator
// container. The operator is the slim pipeline image, which has no
// `buggy-cli` script, so the command runs as a module.
func demoHuntCommand() []string {
	return []string{
		"python", "-m", "buggy.cli", "hunt", demoTarget,
		"--lab", "--no-agent", "--yes", "--rps", "50",
		"--engagement-name", demoEngagement,
	}
}

// demoWaitScript exits 0 once the practice target accepts connections, and 1
// after two minutes without one. Compose reports the target as started as
// soon as its process runs, which is several seconds before it listens.
const demoWaitScript = "import socket, sys, time\n" +
	"deadline = time.monotonic() + 120\n" +
	"while time.monotonic() < deadline:\n" +
	"    try:\n" +
	"        socket.create_connection(('" + demoTargetHost + "', " + demoTargetPort + "), 3).close()\n" +
	"        sys.exit(0)\n" +
	"    except OSError:\n" +
	"        time.sleep(2)\n" +
	"sys.exit(1)\n"

// demoWaitCommand runs demoWaitScript in the pipeline container: the one
// lite service on the lab network, and the one that will scan the target.
func demoWaitCommand() (service string, command []string) {
	return "pipeline", []string{"python", "-c", demoWaitScript}
}

// demoReportPath is where the demo's recon report lands on the host.
func demoReportPath() string {
	return filepath.Join(config.BuggyHome(), "control", demoEngagement, "recon-report.md")
}

func runDemo(cmd *cobra.Command, args []string) error {
	c := demoCompose()
	if demoDown {
		ui.Info("Removing the demo stack...")
		if err := c.Down(); err != nil {
			return err
		}
		ui.Success("Demo removed. Reports stay under " + filepath.Dir(demoReportPath()))
		return nil
	}

	// The demo never calls a model: like `hunt --lite` it is not held to the
	// model-auth gate.
	_, env, err := prepareStackFor(cmd, true)
	if err != nil {
		return err
	}
	if err := ensureComposeFiles(env, c); err != nil {
		return err
	}
	if err := startLiteServices(env, c, demoServices...); err != nil {
		return err
	}

	ui.Info("Waiting for " + demoTarget + " to accept connections...")
	waitService, waitCommand := demoWaitCommand()
	if err := c.Exec(waitService, waitCommand...); err != nil {
		// Not fatal: the hunt below reports what recon could reach.
		ui.Warning("The practice target did not answer in time; recon may find nothing: " + err.Error())
	}

	hunt := demoHuntCommand()
	ui.Info("Starting demo hunt: " + strings.Join(hunt[3:], " "))
	if err := c.RunInteractive([]string{compose.Profiles.Operator}, "operator", nil, hunt...); err != nil {
		return err
	}

	ui.Success("Demo finished. Recon report: " + demoReportPath())
	ui.DimText("The demo stack is still running. Remove it with 'buggy demo --down'.")
	return nil
}
