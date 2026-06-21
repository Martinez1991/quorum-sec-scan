// Package correlate enriches normalized findings (alias resolution for VULN,
// crosswalk resolution for MISCONFIG/K8S) and stamps each with a deterministic
// CorrelationKey + Fingerprint. Grouping itself happens in the consensus
// engine; this package owns identity.
package correlate

import (
	"context"

	"github.com/quorum-sec/quorum/internal/alias"
	"github.com/quorum-sec/quorum/internal/crosswalk"
	"github.com/quorum-sec/quorum/internal/model"
)

// Correlator enriches and keys findings.
type Correlator struct {
	Alias     alias.Resolver
	Crosswalk *crosswalk.Crosswalk
}

// New builds a Correlator. Either dependency may be nil (alias resolution and
// crosswalk are then skipped, and findings degrade to id-as-is / unmapped).
func New(a alias.Resolver, cw *crosswalk.Crosswalk) *Correlator {
	return &Correlator{Alias: a, Crosswalk: cw}
}

// Enrich resolves aliases/controls and assigns CorrelationKey + Fingerprint to
// every finding, returning the same slice mutated in place.
func (c *Correlator) Enrich(ctx context.Context, findings []model.Finding) []model.Finding {
	for i := range findings {
		f := &findings[i]
		switch f.Type {
		case model.TypeVuln:
			c.resolveVuln(ctx, f)
		case model.TypeMisconfig, model.TypeK8sPosture, model.TypeImgHardening:
			c.resolveControl(f)
		}
		f.CorrelationKey = BuildKey(*f)
		f.Fingerprint = Fingerprint(f.CorrelationKey)
	}
	return findings
}

func (c *Correlator) resolveVuln(ctx context.Context, f *model.Finding) {
	if c.Alias == nil || f.VulnID == "" {
		return
	}
	f.VulnID = c.Alias.Canonical(ctx, f.VulnID, f.Aliases)
}

func (c *Correlator) resolveControl(f *model.Finding) {
	// Already canonical (e.g. Trivy emits AVD ids directly).
	if f.CanonicalControl != "" {
		return
	}
	if c.Crosswalk == nil || f.RuleID == "" {
		f.Unmapped = true
		return
	}
	res, ok := c.Crosswalk.Resolve(f.Scanner, f.RuleID)
	if !ok {
		// Never guess a match — isolate and flag (DESIGN §6 rule do não-match).
		f.Unmapped = true
		return
	}
	f.CanonicalControl = res.Control
	if f.Category == "" {
		f.Category = res.Category
	}
	if f.Title == "" && res.Title != "" {
		f.Title = res.Title
	}
}
