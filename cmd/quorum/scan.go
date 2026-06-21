package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/alias"
	"github.com/quorum-sec/quorum/internal/cache"
	"github.com/quorum-sec/quorum/internal/correlate"
	"github.com/quorum-sec/quorum/internal/crosswalk"
	"github.com/quorum-sec/quorum/internal/filter"
	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/orchestrator"
	"github.com/quorum-sec/quorum/internal/report"
	"github.com/quorum-sec/quorum/internal/severity"
	"github.com/spf13/cobra"
)

type scanFlags struct {
	targetType string
	scanners   string
	format     string
	output     string
	failOn     string
	minSev     string
	baseline   string
	crosswalk  string
	cachePath  string
	timeout    time.Duration
	offline    bool
	quiet      bool
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target with the scanner pool and emit a consensus report",
		Long: "Scan a container image, repository/IaC directory, or k8s manifests.\n" +
			"Runs every supported scanner (or those given via --scanners) in parallel,\n" +
			"correlates equivalent findings, and writes a unified report.\n\n" +
			"Exit codes: 0 = ok (or no finding met --fail-on); 1 = a finding met\n" +
			"--fail-on; 2 = usage/runtime error.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.targetType, "type", "", "target type: image|repo|k8s (inferred if omitted)")
	fl.StringVar(&f.scanners, "scanners", "", "comma-separated scanners to run (default: all that support the target)")
	fl.StringVarP(&f.format, "format", "f", "sarif", "output format: sarif|json|xml")
	fl.StringVarP(&f.output, "output", "o", "", "output file (default: stdout)")
	fl.StringVar(&f.failOn, "fail-on", "", "exit non-zero if any finding is >= this severity: critical|high|medium|low")
	fl.StringVar(&f.minSev, "min-severity", "", "drop findings below this severity from the report/gating: critical|high|medium|low")
	fl.StringVar(&f.baseline, "baseline", ".quorumignore", "baseline file of fingerprints/correlationKeys to suppress")
	fl.StringVar(&f.crosswalk, "crosswalk", "./crosswalk", "directory of crosswalk mapping files")
	fl.StringVar(&f.cachePath, "cache", defaultCachePath(), "alias resolver cache file")
	fl.DurationVar(&f.timeout, "timeout", 5*time.Minute, "per-scanner timeout")
	fl.BoolVar(&f.offline, "offline", false, "disable OSV alias lookups (use scanner-local aliases + cache only)")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "suppress progress logs on stderr")
	return cmd
}

func runScan(cmd *cobra.Command, target string, f *scanFlags) error {
	tt, err := resolveTargetType(f.targetType, target)
	if err != nil {
		return err
	}

	var failThreshold model.Severity
	gating := false
	if f.failOn != "" {
		sev, ok := severity.Parse(f.failOn)
		if !ok {
			return fmt.Errorf("invalid --fail-on %q (want critical|high|medium|low)", f.failOn)
		}
		failThreshold = sev
		gating = true
	}

	minSeverity := model.SevUnknown
	if f.minSev != "" {
		sev, ok := severity.Parse(f.minSev)
		if !ok {
			return fmt.Errorf("invalid --min-severity %q (want critical|high|medium|low)", f.minSev)
		}
		minSeverity = sev
	}

	baseline, present, err := filter.LoadBaseline(f.baseline)
	if err != nil {
		return fmt.Errorf("loading baseline: %w", err)
	}
	if !present && cmd.Flags().Changed("baseline") {
		return fmt.Errorf("baseline file not found: %s", f.baseline)
	}

	format, err := report.ParseFormat(f.format)
	if err != nil {
		return err
	}

	cw, err := crosswalk.Load(f.crosswalk)
	if err != nil {
		return fmt.Errorf("loading crosswalk: %w", err)
	}

	store := cache.Open(f.cachePath)
	var osv *alias.OSVClient
	if !f.offline {
		osv = alias.NewOSVClient()
	}
	correlator := correlate.New(alias.New(store, osv), cw)

	logf := func(format string, args ...any) {
		if !f.quiet {
			fmt.Fprintf(os.Stderr, "[quorum] "+format+"\n", args...)
		}
	}
	logf("target=%s type=%s crosswalk=%d rules offline=%v", target, tt, cw.Len(), f.offline)

	tgt := adapter.Target{Type: tt, Ref: target}
	res, err := orchestrator.Run(context.Background(), tgt, orchestrator.Options{
		Scanners:       splitScanners(f.scanners),
		PerScannerTime: f.timeout,
		Correlator:     correlator,
		Logf:           logf,
	})
	if err != nil {
		return err
	}

	// Post-process: suppress baseline-listed findings and those below the
	// minimum severity, before reporting and gating.
	fr := filter.Apply(res.Merged, minSeverity, baseline)
	res.Merged = fr.Kept
	if fr.SuppressedBaseline > 0 || fr.SuppressedSeverity > 0 {
		logf("filtered: %d suppressed by baseline (%d entries), %d below min-severity %s",
			fr.SuppressedBaseline, baseline.Len(), fr.SuppressedSeverity, minSeverity)
	}

	if err := emit(cmd, res, format, f.output); err != nil {
		return err
	}
	printSummary(res, f.quiet)

	if gating {
		if worst := worstSeverity(res); severity.AtLeast(worst, failThreshold) {
			logf("gate: found %s finding >= --fail-on %s → exit 1", worst, failThreshold)
			os.Exit(1)
		}
	}
	return nil
}

func emit(cmd *cobra.Command, res *orchestrator.Result, format report.Format, output string) error {
	var buf bytes.Buffer
	if err := report.Write(&buf, res, format); err != nil {
		return err
	}
	if output == "" {
		_, err := cmd.OutOrStdout().Write(buf.Bytes())
		return err
	}
	if dir := filepath.Dir(output); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(output, buf.Bytes(), 0o644)
}

func printSummary(res *orchestrator.Result, quiet bool) {
	if quiet {
		return
	}
	w := os.Stderr
	fmt.Fprintf(w, "\n── quorum summary ───────────────────────────\n")
	for _, r := range res.Runs {
		extra := ""
		if r.Error != "" {
			extra = "  (" + truncate(r.Error, 60) + ")"
		}
		fmt.Fprintf(w, "  %-10s %-12s %3d findings%s\n", r.Name, r.Status, r.Findings, extra)
	}
	bySev := map[model.Severity]int{}
	multi := 0
	for _, m := range res.Merged {
		bySev[m.Severity]++
		if m.DetectionCount > 1 {
			multi++
		}
	}
	fmt.Fprintf(w, "  ----------------------------------------\n")
	fmt.Fprintf(w, "  %d findings after consensus  (%d multi-detected)\n", len(res.Merged), multi)
	fmt.Fprintf(w, "  CRIT %d  HIGH %d  MED %d  LOW %d  INFO %d\n",
		bySev[model.SevCritical], bySev[model.SevHigh], bySev[model.SevMedium],
		bySev[model.SevLow], bySev[model.SevInfo])
	fmt.Fprintf(w, "  elapsed %s\n", res.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "  note: 0 findings is not proof of safety — see scanner statuses above.\n")
}

func worstSeverity(res *orchestrator.Result) model.Severity {
	worst := model.SevUnknown
	for _, m := range res.Merged {
		if m.Severity.Rank() > worst.Rank() {
			worst = m.Severity
		}
	}
	return worst
}

func resolveTargetType(explicit, ref string) (adapter.TargetType, error) {
	switch strings.ToLower(explicit) {
	case "image":
		return adapter.TargetImage, nil
	case "repo", "fs", "dir":
		return adapter.TargetRepo, nil
	case "k8s", "kubernetes", "manifests":
		return adapter.TargetK8s, nil
	case "":
		// infer: an existing path on disk is a repo; otherwise an image ref.
		if _, err := os.Stat(ref); err == nil {
			return adapter.TargetRepo, nil
		}
		return adapter.TargetImage, nil
	default:
		return "", fmt.Errorf("invalid --type %q (want image|repo|k8s)", explicit)
	}
}

func splitScanners(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func defaultCachePath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "quorum", "aliases.json")
	}
	return ".quorum-cache.json"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
