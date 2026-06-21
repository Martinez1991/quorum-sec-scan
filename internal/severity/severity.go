// Package severity holds the single normalization table every scanner's
// severity converges to (DESIGN §10).
package severity

import (
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
)

// FromCVSS maps a CVSS base score to the canonical scale.
//
//	>=9.0 CRITICAL | >=7.0 HIGH | >=4.0 MEDIUM | >0 LOW | 0 UNKNOWN
func FromCVSS(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SevCritical
	case score >= 7.0:
		return model.SevHigh
	case score >= 4.0:
		return model.SevMedium
	case score > 0:
		return model.SevLow
	default:
		return model.SevUnknown
	}
}

// FromLabel maps a free-text severity label (Trivy/Grype/Checkov/KICS/
// Kubescape enums) to the canonical scale. Case-insensitive.
func FromLabel(label string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL", "CRIT":
		return model.SevCritical
	case "HIGH", "ERROR", "DANGER":
		return model.SevHigh
	case "MEDIUM", "MODERATE", "WARNING", "WARN":
		return model.SevMedium
	case "LOW", "MINOR":
		return model.SevLow
	case "INFO", "INFORMATIONAL", "NEGLIGIBLE", "UNKNOWN", "NONE", "":
		if label == "" {
			return model.SevUnknown
		}
		if strings.EqualFold(label, "unknown") || strings.EqualFold(label, "none") {
			return model.SevUnknown
		}
		return model.SevInfo
	default:
		return model.SevUnknown
	}
}

// FromDockle maps Dockle's labels: FATAL->HIGH, WARN->MEDIUM, INFO->LOW.
func FromDockle(label string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "FATAL":
		return model.SevHigh
	case "WARN":
		return model.SevMedium
	case "INFO":
		return model.SevLow
	case "PASS", "SKIP", "IGNORE":
		return model.SevInfo
	default:
		return model.SevUnknown
	}
}

// Max returns the highest severity among the given values.
func Max(sevs ...model.Severity) model.Severity {
	best := model.SevUnknown
	for _, s := range sevs {
		if s.Rank() > best.Rank() {
			best = s
		}
	}
	return best
}

// AtLeast reports whether s meets or exceeds threshold (used by --fail-on).
func AtLeast(s, threshold model.Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// Parse turns a CLI flag value ("high") into a canonical Severity.
func Parse(s string) (model.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SevCritical, true
	case "HIGH":
		return model.SevHigh, true
	case "MEDIUM":
		return model.SevMedium, true
	case "LOW":
		return model.SevLow, true
	case "INFO":
		return model.SevInfo, true
	default:
		return model.SevUnknown, false
	}
}
