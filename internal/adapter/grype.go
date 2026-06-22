package adapter

import (
	"context"
	"encoding/json"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/purl"
	"github.com/quorum-sec/quorum/internal/severity"
)

func init() { Register(&grype{}) }

type grype struct{}

func (grype) Name() string { return "grype" }

func (g grype) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "grype", "version")
}

func (grype) Supports(target Target) bool {
	return target.Type == TargetImage || target.Type == TargetRepo
}

func (grype) Capabilities() []Capability {
	return []Capability{{Type: model.TypeVuln, Targets: []TargetType{TargetImage, TargetRepo}}}
}

func (g grype) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	ref := target.Ref
	if target.Type == TargetRepo {
		ref = "dir:" + ref
	}
	// No -q: grype's --quiet also suppresses error logging, which would leave a
	// failure with an empty stderr ("exit status 1:" and nothing else). runCmd
	// only surfaces stderr on failure, so the progress noise on success is
	// discarded anyway — keeping logs on buys us a real diagnostic when it fails.
	out, err := runCmd(ctx, "grype", ref, "-o", "json")
	if err != nil {
		return nil, err
	}
	ver, _ := g.Version(ctx)
	return g.parse(out, ver)
}

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			CVSS        []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		Version string `json:"version"`
		Name    string `json:"name"`
	} `json:"descriptor"`
}

func (g grype) parse(data []byte, ver string) ([]model.Finding, error) {
	var rep grypeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	if rep.Descriptor.Version != "" && ver == "" {
		ver = rep.Descriptor.Version
	}
	var out []model.Finding
	for _, m := range rep.Matches {
		var aliases []string
		confirmed := false
		for _, rv := range m.RelatedVulnerabilities {
			aliases = append(aliases, rv.ID)
			if len(rv.ID) >= 4 && (rv.ID[:4] == "CVE-" || rv.ID[:4] == "cve-") {
				confirmed = true
			}
		}
		p := m.Artifact.PURL
		if p == "" {
			p = purl.Build(m.Artifact.Type, "", m.Artifact.Name, m.Artifact.Version)
		}
		cvss := 0.0
		for _, c := range m.Vulnerability.CVSS {
			if c.Metrics.BaseScore > cvss {
				cvss = c.Metrics.BaseScore
			}
		}
		sev := severity.FromLabel(m.Vulnerability.Severity)
		if sev == model.SevUnknown && cvss > 0 {
			sev = severity.FromCVSS(cvss)
		}
		out = append(out, model.Finding{
			Type:           model.TypeVuln,
			Scanner:        "grype",
			ScannerVersion: ver,
			VulnID:         m.Vulnerability.ID,
			Aliases:        aliases,
			PURL:           p,
			Severity:       sev,
			CVSS:           cvss,
			Title:          m.Vulnerability.ID + " in " + m.Artifact.Name,
			Description:    m.Vulnerability.Description,
			Confirmed:      confirmed,
		})
	}
	return out, nil
}
