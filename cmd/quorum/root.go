package main

import (
	"fmt"
	"sort"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/report"
	"github.com/spf13/cobra"
)

// build-time overridable version (set via -ldflags "-X main.version=...").
var version = "0.1.0"

func newRootCmd() *cobra.Command {
	report.Version = version
	root := &cobra.Command{
		Use:   "quorum",
		Short: "Consensus security scanning across multiple open-source scanners",
		Long: "Quorum orchestrates a pool of open-source security scanners over a target,\n" +
			"normalizes every finding to a canonical model, correlates equivalent findings\n" +
			"across tools, and reports how many and which scanners detected each issue plus\n" +
			"a consensus confidence score. Built for CI/CD: configure via flags, gate via\n" +
			"exit code. No panel, no daemon.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newListScannersCmd())
	return root
}

func newListScannersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-scanners",
		Short: "List the registered scanner adapters and their capabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			names := adapter.Names()
			sort.Strings(names)
			for _, n := range names {
				a, _ := adapter.Get(n)
				caps := a.Capabilities()
				types := make([]string, 0, len(caps))
				for _, c := range caps {
					types = append(types, string(c.Type))
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-12s %v\n", n, types)
			}
			return nil
		},
	}
}
