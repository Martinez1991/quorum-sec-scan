package adapter

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/purl"
	"github.com/quorum-sec/quorum/internal/severity"
)

// avdLikeRe matches a bare AVD control id without the "AVD-" prefix, e.g.
// "AWS-0086" or "GCP-0012" — the form Trivy >= ~0.60 emits in the Misconfig
// "ID" field after dropping the dedicated AVDID field.
var avdLikeRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]+$`)

// normalizeAVD canonicalizes a Trivy misconfig id to the "AVD-<provider>-<n>"
// form the crosswalk and the rest of the pipeline use. Already-prefixed ids and
// non-AVD slugs pass through unchanged.
func normalizeAVD(id string) string {
	if id == "" || strings.HasPrefix(id, "AVD-") {
		return id
	}
	if avdLikeRe.MatchString(id) {
		return "AVD-" + id
	}
	return id
}

func init() { Register(&trivy{}) }

type trivy struct{}

func (trivy) Name() string { return "trivy" }

func (t trivy) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "trivy", "--version")
}

func (trivy) Supports(target Target) bool {
	switch target.Type {
	case TargetImage, TargetRepo, TargetK8s:
		return true
	default:
		return false
	}
}

func (trivy) Capabilities() []Capability {
	return []Capability{
		{Type: model.TypeVuln, Targets: []TargetType{TargetImage, TargetRepo}},
		{Type: model.TypeMisconfig, Targets: []TargetType{TargetRepo, TargetK8s}},
		{Type: model.TypeSecret, Targets: []TargetType{TargetImage, TargetRepo}},
	}
}

func (t trivy) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	args := []string{}
	switch target.Type {
	case TargetImage:
		args = []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", target.Ref}
	default: // repo, k8s
		args = []string{"fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", target.Ref}
	}
	out, err := runCmd(ctx, "trivy", args...)
	if err != nil {
		return nil, err
	}
	ver, _ := t.Version(ctx)
	return t.parse(out, ver)
}

type trivyReport struct {
	Results []struct {
		Target            string `json:"Target"`
		Class             string `json:"Class"`
		Type              string `json:"Type"`
		Vulnerabilities   []trivyVuln
		Misconfigurations []trivyMisconf
		Secrets           []trivySecret
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	Severity    string `json:"Severity"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	CVSS        map[string]struct {
		V3Score float64 `json:"V3Score"`
		V2Score float64 `json:"V2Score"`
	} `json:"CVSS"`
	DataSource *struct {
		Name string `json:"Name"`
	} `json:"DataSource"`
}

type trivyMisconf struct {
	Type          string `json:"Type"`
	ID            string `json:"ID"`
	AVDID         string `json:"AVDID"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Severity      string `json:"Severity"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

func (t trivy) parse(data []byte, ver string) ([]model.Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			p := v.PkgIdentifier.PURL
			if p == "" {
				p = purl.Build(r.Type, "", v.PkgName, v.InstalledVersion)
			}
			cvss := maxCVSS(v.CVSS)
			sev := severity.FromLabel(v.Severity)
			if sev == model.SevUnknown && cvss > 0 {
				sev = severity.FromCVSS(cvss)
			}
			out = append(out, model.Finding{
				Type:           model.TypeVuln,
				Scanner:        "trivy",
				ScannerVersion: ver,
				VulnID:         v.VulnerabilityID,
				PURL:           p,
				Severity:       sev,
				CVSS:           cvss,
				Title:          firstNonEmpty(v.Title, v.VulnerabilityID),
				Description:    v.Description,
				Confirmed:      v.DataSource != nil,
				Location:       model.Location{File: r.Target},
			})
		}
		for _, m := range r.Misconfigurations {
			raw := firstNonEmpty(m.AVDID, m.ID)
			out = append(out, model.Finding{
				Type:             model.TypeMisconfig,
				Scanner:          "trivy",
				ScannerVersion:   ver,
				RuleID:           raw,
				CanonicalControl: normalizeAVD(raw), // Trivy speaks AVD; newer versions drop the "AVD-" prefix
				Severity:         severity.FromLabel(m.Severity),
				Title:            m.Title,
				Description:      m.Description,
				Resource:         model.Resource{Address: m.CauseMetadata.Resource},
				Location: model.Location{
					File:      r.Target,
					StartLine: m.CauseMetadata.StartLine,
					EndLine:   m.CauseMetadata.EndLine,
				},
			})
		}
		for _, s := range r.Secrets {
			out = append(out, model.Finding{
				Type:           model.TypeSecret,
				Scanner:        "trivy",
				ScannerVersion: ver,
				RuleID:         s.RuleID,
				Severity:       severity.FromLabel(s.Severity),
				Title:          firstNonEmpty(s.Title, s.Category, s.RuleID),
				Location:       model.Location{File: r.Target, StartLine: s.StartLine, EndLine: s.EndLine},
			})
		}
	}
	return out, nil
}

func maxCVSS(m map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) float64 {
	best := 0.0
	for _, c := range m {
		if c.V3Score > best {
			best = c.V3Score
		}
		if c.V2Score > best {
			best = c.V2Score
		}
	}
	return best
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
