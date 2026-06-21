// Package alias resolves any vuln identifier to a canonical form (preferring
// CVE) so that Grype's GHSA-xxxx and Trivy's CVE-yyyy for the same bug
// correlate instead of splitting (DESIGN §7).
package alias

import (
	"context"
	"strings"

	"github.com/quorum-sec/quorum/internal/cache"
)

// Resolver maps any vuln id to its canonical form.
type Resolver interface {
	Canonical(ctx context.Context, id string, knownAliases []string) string
}

// osvSource is the subset of OSVClient the chain depends on (so tests can stub).
type osvSource interface {
	Aliases(ctx context.Context, id string) ([]string, error)
}

// chainResolver tries, in order: aliases already on the finding, the local
// cache, then OSV. It never returns an error — on any failure it degrades to
// the best id it has.
type chainResolver struct {
	local *cache.Store
	osv   osvSource
}

// New builds the layered resolver. Pass a nil osv to disable network lookups
// (offline mode); the resolver then relies only on finding-local aliases and
// the cache.
func New(local *cache.Store, osv osvSource) Resolver {
	return &chainResolver{local: local, osv: osv}
}

func (r *chainResolver) Canonical(ctx context.Context, id string, knownAliases []string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return id
	}

	// Layer 1: aliases the scanner already handed us. If a CVE is in there,
	// we are done without touching cache or network.
	if c := preferCVE(append([]string{id}, knownAliases...)); isCVE(c) {
		return c
	}

	// Layer 2: local cache.
	if v, ok := r.local.Get(id); ok {
		return v
	}

	// Layer 3: OSV arbiter. Graceful degradation on any error.
	canon := preferCVE(append([]string{id}, knownAliases...))
	if r.osv != nil {
		if aliases, err := r.osv.Aliases(ctx, id); err == nil {
			canon = preferCVE(append(aliases, id))
		}
	}
	r.local.Put(id, canon)
	return canon
}

// preferCVE picks the best id from a set: CVE > GHSA > first non-empty.
func preferCVE(ids []string) string {
	var ghsa, first string
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if first == "" {
			first = id
		}
		if isCVE(id) {
			return strings.ToUpper(id)
		}
		if ghsa == "" && strings.HasPrefix(strings.ToUpper(id), "GHSA-") {
			ghsa = id
		}
	}
	if ghsa != "" {
		return ghsa
	}
	return first
}

func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-")
}
