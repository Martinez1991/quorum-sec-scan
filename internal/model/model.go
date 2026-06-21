// Package model defines the canonical data model. Nothing in the pipeline
// operates on a scanner's raw JSON — every adapter normalizes into Finding,
// and every later stage (alias, correlate, consensus, report) speaks Finding
// and MergedFinding only.
package model

// FindingType classifies a finding and selects the correlation strategy.
type FindingType string

const (
	TypeVuln         FindingType = "VULN"
	TypeMisconfig    FindingType = "MISCONFIG"
	TypeSecret       FindingType = "SECRET"
	TypeK8sPosture   FindingType = "K8S_POSTURE"
	TypeImgHardening FindingType = "IMG_HARDENING"
)

// Severity is the single normalized severity scale everything converges to.
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
	SevUnknown  Severity = "UNKNOWN"
)

// Rank returns an orderable weight so severities can be compared/aggregated.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

// Resource identifies the IaC/k8s object a finding applies to.
type Resource struct {
	Kind      string `json:"kind,omitempty"`      // aws_s3_bucket | Deployment
	Name      string `json:"name,omitempty"`      //
	Namespace string `json:"namespace,omitempty"` // k8s
	Address   string `json:"address,omitempty"`   // canonical: "<type>.<name>"
}

// Location pins a finding to a file/line or image layer.
type Location struct {
	File       string `json:"file,omitempty"`
	StartLine  int    `json:"startLine,omitempty"`
	EndLine    int    `json:"endLine,omitempty"`
	ImageLayer string `json:"imageLayer,omitempty"` // SCA
}

// Finding is the canonical unit. Every adapter emits this; adapters never
// compute CorrelationKey — that is centralized in the correlator.
type Finding struct {
	Type           FindingType `json:"type"`
	Scanner        string      `json:"scanner"`
	ScannerVersion string      `json:"scannerVersion,omitempty"`

	// Identity (populated per Type)
	VulnID           string   `json:"vulnId,omitempty"`           // CVE/GHSA, canonical after alias resolve
	Aliases          []string `json:"aliases,omitempty"`          // other ids the scanner reported
	PURL             string   `json:"purl,omitempty"`             // pkg:type/ns/name@version
	RuleID           string   `json:"ruleId,omitempty"`           // scanner-native rule id (crosswalk input)
	CanonicalControl string   `json:"canonicalControl,omitempty"` // crosswalk result (AVD/CWE/CIS/category)
	Category         string   `json:"category,omitempty"`         // semantic category (crosswalk fallback)
	Unmapped         bool     `json:"unmapped,omitempty"`         // crosswalk could not resolve a control
	Resource         Resource `json:"resource,omitempty"`
	Location         Location `json:"location,omitempty"`

	// Normalized
	Severity Severity `json:"severity"`
	CVSS     float64  `json:"cvss,omitempty"` // 0 = absent

	// Computed by the pipeline
	CorrelationKey string `json:"correlationKey,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"` // sha256(CorrelationKey)

	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Confirmed   bool           `json:"confirmed,omitempty"` // confirmed by NVD/OSV authoritative source
	Raw         map[string]any `json:"-"`                   // original payload, not serialized by default
}

// MergedFinding is the post-correlation, post-consensus unit.
type MergedFinding struct {
	CorrelationKey string      `json:"correlationKey"`
	Type           FindingType `json:"type"`
	Title          string      `json:"title"`
	Severity       Severity    `json:"severity"` // aggregated (max)
	DetectedBy     []string    `json:"detectedBy"`
	DetectionCount int         `json:"detectionCount"`
	Confidence     float64     `json:"confidence"` // 0..1
	Unmapped       bool        `json:"unmapped,omitempty"`
	Members        []Finding   `json:"members"`
	Fingerprint    string      `json:"fingerprint"`
}
