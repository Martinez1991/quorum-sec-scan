// Package orchestrator resolves which adapters to run for a target, fans them
// out in parallel with a per-scanner timeout, and collects canonical findings.
// Pipeline: scan → normalize → resolve aliases → correlate → score → report.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/consensus"
	"github.com/quorum-sec/quorum/internal/correlate"
	"github.com/quorum-sec/quorum/internal/model"
)

// defaultProbeTime is how long to wait for a scanner's version probe before
// giving up. Generous on purpose: heavy tools (e.g. checkov, a Python process)
// can be slow to cold-start, especially while every scanner launches at once on
// a memory-constrained runner. Too tight a budget marks a working tool as
// "unavailable" when its probe is merely SIGKILLed mid-startup.
const defaultProbeTime = 60 * time.Second

// ScannerRun records what happened with one scanner (for transparency in the
// report — "0 vulns" must never look like "scan didn't run", DESIGN §14).
type ScannerRun struct {
	Name     string        `json:"name"`
	Version  string        `json:"version,omitempty"`
	Status   string        `json:"status"` // ran | skipped | unavailable | error | timeout
	Findings int           `json:"findings"`
	Duration time.Duration `json:"-"`
	Error    string        `json:"error,omitempty"`
}

// MarshalJSON serializes Duration as whole milliseconds under "durationMs",
// matching the summary block. Without this, time.Duration marshals as raw
// nanoseconds, contradicting the field name.
func (s ScannerRun) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name           string `json:"name"`
		Version        string `json:"version,omitempty"`
		Status         string `json:"status"`
		Findings       int    `json:"findings"`
		DurationMillis int64  `json:"durationMs"`
		Error          string `json:"error,omitempty"`
	}{
		Name:           s.Name,
		Version:        s.Version,
		Status:         s.Status,
		Findings:       s.Findings,
		DurationMillis: s.Duration.Milliseconds(),
		Error:          s.Error,
	})
}

// Result is the full output of a scan.
type Result struct {
	Target    adapter.Target        `json:"target"`
	Runs      []ScannerRun          `json:"scanners"`
	Findings  []model.Finding       `json:"-"` // raw canonical findings (kept for JSON reporter detail)
	Merged    []model.MergedFinding `json:"findings"`
	StartedAt time.Time             `json:"-"`
	Duration  time.Duration         `json:"durationMs"`
}

// Options configure a scan.
type Options struct {
	Scanners       []string      // empty = all registered that support the target
	PerScannerTime time.Duration // per-scanner timeout (0 = no extra timeout)
	ProbeTime      time.Duration // version-probe timeout (0 = defaultProbeTime)
	Correlator     *correlate.Correlator
	Logf           func(format string, args ...any) // optional progress logger
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Run executes the full pipeline and returns the scored result.
func Run(ctx context.Context, target adapter.Target, opts Options) (*Result, error) {
	start := time.Now()
	adapters, unknown := selectAdapters(target, opts.Scanners)
	for _, name := range unknown {
		opts.logf("warning: unknown scanner %q ignored (known: %s)", name, strings.Join(knownNames(), ", "))
	}

	res := &Result{Target: target, StartedAt: start}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		all []model.Finding
	)

	for _, a := range adapters {
		a := a
		wg.Add(1)
		go func() {
			defer wg.Done()
			run := runOne(ctx, a, target, opts)
			mu.Lock()
			res.Runs = append(res.Runs, run.summary)
			all = append(all, run.findings...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(res.Runs, func(i, j int) bool { return res.Runs[i].Name < res.Runs[j].Name })

	// normalize/resolve aliases + crosswalk + key, then consensus.
	if opts.Correlator != nil {
		all = opts.Correlator.Enrich(ctx, all)
	} else {
		// Still need keys for grouping even without enrichment.
		for i := range all {
			all[i].CorrelationKey = correlate.BuildKey(all[i])
			all[i].Fingerprint = correlate.Fingerprint(all[i].CorrelationKey)
		}
	}
	res.Findings = all
	res.Merged = consensus.Merge(all)
	res.Duration = time.Since(start)
	return res, nil
}

type oneResult struct {
	summary  ScannerRun
	findings []model.Finding
}

func runOne(ctx context.Context, a adapter.Adapter, target adapter.Target, opts Options) oneResult {
	name := a.Name()
	sr := ScannerRun{Name: name}

	if !a.Supports(target) {
		sr.Status = "skipped"
		opts.logf("skip %s: does not support target %s", name, target.Type)
		return oneResult{summary: sr}
	}

	probeTime := opts.ProbeTime
	if probeTime <= 0 {
		probeTime = defaultProbeTime
	}
	verCtx, cancelVer := context.WithTimeout(ctx, probeTime)
	ver, err := a.Version(verCtx)
	probeTimedOut := verCtx.Err() == context.DeadlineExceeded
	cancelVer()
	if err != nil {
		sr.Status = "unavailable"
		switch {
		case probeTimedOut:
			sr.Error = fmt.Sprintf("version probe exceeded %s — tool too slow to start or resource-starved (give the container more memory, or scope --scanners): %v", probeTime, err)
			opts.logf("skip %s: version probe timed out after %s (slow start / low memory?)", name, probeTime)
		case killedSignal(err):
			sr.Error = fmt.Sprintf("version probe killed — likely out of memory; raise the container's memory limit: %v", err)
			opts.logf("skip %s: version probe killed (likely OOM — increase container memory)", name)
		default:
			sr.Error = err.Error()
			opts.logf("skip %s: not installed/available", name)
		}
		return oneResult{summary: sr}
	}
	sr.Version = ver

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.PerScannerTime > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.PerScannerTime)
		defer cancel()
	}

	opts.logf("run  %s (%s) ...", name, ver)
	t0 := time.Now()
	findings, err := a.Run(runCtx, target)
	sr.Duration = time.Since(t0)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			sr.Status = "timeout"
		} else {
			sr.Status = "error"
		}
		sr.Error = err.Error()
		opts.logf("fail %s: %v", name, err)
		return oneResult{summary: sr}
	}
	sr.Status = "ran"
	sr.Findings = len(findings)
	opts.logf("done %s: %d findings in %s", name, len(findings), sr.Duration.Round(time.Millisecond))
	return oneResult{summary: sr, findings: findings}
}

// selectAdapters resolves the requested scanner names to adapters. When the
// request is empty, every registered adapter runs. Names with no matching
// adapter are returned in `unknown` so the caller can warn instead of silently
// dropping them.
func selectAdapters(target adapter.Target, requested []string) (sel []adapter.Adapter, unknown []string) {
	if len(requested) == 0 {
		out := adapter.All()
		sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
		return out, nil
	}
	for _, name := range requested {
		if a, ok := adapter.Get(name); ok {
			sel = append(sel, a)
		} else {
			unknown = append(unknown, name)
		}
	}
	return sel, unknown
}

// knownNames returns the registered scanner names, sorted, for diagnostics.
func knownNames() []string {
	n := adapter.Names()
	sort.Strings(n)
	return n
}

// killedSignal reports whether err looks like the OS killed the process
// (SIGKILL) — typically the OOM killer — as opposed to the binary being absent.
func killedSignal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "signal: killed")
}
