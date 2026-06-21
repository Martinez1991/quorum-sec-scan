// Package consensus groups correlated findings and scores each group. Raw
// detection count is not confidence — diversity of engine, severity, and
// authoritative confirmation are weighed too (DESIGN §9).
package consensus

import (
	"math"
	"sort"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/severity"
)

// scannerCategory groups scanners by engine family so that two *different*
// engines agreeing counts for more than two of the same family.
var scannerCategory = map[string]string{
	"trivy":     "sca",
	"grype":     "sca",
	"checkov":   "iac",
	"kics":      "iac",
	"kubescape": "k8s",
	"polaris":   "k8s",
	"dockle":    "hardening",
}

// Merge groups findings by CorrelationKey and produces scored MergedFindings,
// sorted by descending (severity, confidence, detectionCount) for stable,
// useful report ordering.
func Merge(findings []model.Finding) []model.MergedFinding {
	groups := map[string][]model.Finding{}
	order := []string{}
	for _, f := range findings {
		if _, seen := groups[f.CorrelationKey]; !seen {
			order = append(order, f.CorrelationKey)
		}
		groups[f.CorrelationKey] = append(groups[f.CorrelationKey], f)
	}

	out := make([]model.MergedFinding, 0, len(groups))
	for _, key := range order {
		members := groups[key]
		scanners := distinctScanners(members)
		agg := aggregateSeverity(members)
		m := model.MergedFinding{
			CorrelationKey: key,
			Type:           members[0].Type,
			Title:          bestTitle(members),
			Severity:       agg,
			DetectedBy:     scanners,
			DetectionCount: len(scanners),
			Members:        members,
			Fingerprint:    members[0].Fingerprint,
			Unmapped:       anyUnmapped(members),
			Confidence:     confidence(members, scanners, agg),
		}
		out = append(out, m)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if a, b := out[i].Severity.Rank(), out[j].Severity.Rank(); a != b {
			return a > b
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		if out[i].DetectionCount != out[j].DetectionCount {
			return out[i].DetectionCount > out[j].DetectionCount
		}
		return out[i].CorrelationKey < out[j].CorrelationKey
	})
	return out
}

// confidence implements DESIGN §9. Weights: count .35, diversity .25,
// severity .25, authoritative .15.
func confidence(members []model.Finding, scanners []string, agg model.Severity) float64 {
	const w1, w2, w3, w4 = 0.35, 0.25, 0.25, 0.15

	count := math.Log(1+float64(len(scanners))) / math.Log(5) // ~normalized, decreasing returns
	diversity := categoryDiversity(scanners)
	sev := severityWeight(agg)
	authoritative := 0.0
	if confirmedByNVDorOSV(members) {
		authoritative = 1.0
	}
	return clamp01(w1*count + w2*diversity + w3*sev + w4*authoritative)
}

// categoryDiversity returns 0..1: how many distinct engine families detected
// this finding, normalized. One family → ~0.33, two → ~0.66, three+ → 1.
func categoryDiversity(scanners []string) float64 {
	cats := map[string]struct{}{}
	for _, s := range scanners {
		c, ok := scannerCategory[strings.ToLower(s)]
		if !ok {
			c = "other:" + strings.ToLower(s)
		}
		cats[c] = struct{}{}
	}
	switch len(cats) {
	case 0:
		return 0
	case 1:
		return 1.0 / 3.0
	case 2:
		return 2.0 / 3.0
	default:
		return 1.0
	}
}

func severityWeight(s model.Severity) float64 {
	switch s {
	case model.SevCritical:
		return 1.0
	case model.SevHigh:
		return 0.8
	case model.SevMedium:
		return 0.5
	case model.SevLow:
		return 0.3
	case model.SevInfo:
		return 0.1
	default:
		return 0.1
	}
}

func confirmedByNVDorOSV(members []model.Finding) bool {
	for _, m := range members {
		if m.Confirmed {
			return true
		}
		// A resolved CVE with a CVSS score is treated as authoritatively backed.
		if m.Type == model.TypeVuln && m.CVSS > 0 && strings.HasPrefix(strings.ToUpper(m.VulnID), "CVE-") {
			return true
		}
	}
	return false
}

func aggregateSeverity(members []model.Finding) model.Severity {
	best := model.SevUnknown
	for _, m := range members {
		best = severity.Max(best, m.Severity)
	}
	return best
}

func distinctScanners(members []model.Finding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range members {
		name := strings.ToLower(m.Scanner)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func bestTitle(members []model.Finding) string {
	for _, m := range members {
		if strings.TrimSpace(m.Title) != "" {
			return m.Title
		}
	}
	return members[0].CorrelationKey
}

func anyUnmapped(members []model.Finding) bool {
	for _, m := range members {
		if m.Unmapped {
			return true
		}
	}
	return false
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
