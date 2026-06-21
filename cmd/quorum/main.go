// Command quorum is a lightweight CLI orchestrator that runs a pool of
// open-source security scanners over a target, correlates equivalent findings
// across tools, and emits a unified consensus report (SARIF/JSON/XML).
//
// It is panel-less and CI/CD-first: configure via flags, gate via exit code.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "quorum:", err)
		os.Exit(2)
	}
}
