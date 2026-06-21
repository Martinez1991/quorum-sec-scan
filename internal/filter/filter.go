// Package filter post-processes merged findings before they are reported or
// gated: a minimum-severity cut and a baseline of suppressed findings. Both are
// essential for CI adoption — without a way to accept known findings, --fail-on
// is unusable noise.
package filter

import (
	"bufio"
	"os"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/severity"
)

// Baseline is a set of finding identities to suppress. An entry matches a
// finding by its Fingerprint OR its CorrelationKey, so users can copy either
// from a report.
type Baseline struct {
	ids map[string]struct{}
}

// LoadBaseline reads a baseline file: one fingerprint or correlationKey per
// line, '#' comments and blank lines ignored. A missing file yields an empty
// baseline and ok=false (so the caller can distinguish "not present" from
// "present but empty"); other read errors are returned.
func LoadBaseline(path string) (*Baseline, bool, error) {
	b := &Baseline{ids: map[string]struct{}{}}
	if path == "" {
		return b, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return b, false, nil
		}
		return nil, false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow "fingerprint  # note" trailing comments.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			b.ids[strings.ToLower(line)] = struct{}{}
		}
	}
	return b, true, sc.Err()
}

// Has reports whether a finding is suppressed by the baseline.
func (b *Baseline) Has(m model.MergedFinding) bool {
	if b == nil || len(b.ids) == 0 {
		return false
	}
	if _, ok := b.ids[strings.ToLower(m.Fingerprint)]; ok {
		return true
	}
	_, ok := b.ids[strings.ToLower(m.CorrelationKey)]
	return ok
}

// Len reports the number of baseline entries.
func (b *Baseline) Len() int {
	if b == nil {
		return 0
	}
	return len(b.ids)
}

// Result reports what a filter pass kept and dropped (for transparency — a
// suppressed finding is still a finding, DESIGN §14).
type Result struct {
	Kept               []model.MergedFinding
	SuppressedBaseline int
	SuppressedSeverity int
}

// Apply drops findings below minSeverity (when set, i.e. not Unknown) and those
// matched by the baseline. Order is preserved.
func Apply(merged []model.MergedFinding, minSeverity model.Severity, baseline *Baseline) Result {
	res := Result{Kept: make([]model.MergedFinding, 0, len(merged))}
	for _, m := range merged {
		if baseline.Has(m) {
			res.SuppressedBaseline++
			continue
		}
		if minSeverity != model.SevUnknown && !severity.AtLeast(m.Severity, minSeverity) {
			res.SuppressedSeverity++
			continue
		}
		res.Kept = append(res.Kept, m)
	}
	return res
}
