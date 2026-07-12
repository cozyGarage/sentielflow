// SentinelFlow - AI-Driven CI/CD Security Gatekeeper
// Main entry point for the CLI application

package main

import (
	"os"

	"github.com/cozygarage/sentinelflow/internal/cli"
)

// Version information (set by build flags)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersionInfo(version, commit, date)

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
