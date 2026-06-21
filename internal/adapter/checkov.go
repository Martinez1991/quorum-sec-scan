package adapter

import (
	"context"
	"encoding/json"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/severity"
)

func init() { Register(&checkov{}) }

type checkov struct{}

func (checkov) Name() string { return "checkov" }

func (c checkov) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "checkov", "--version")
}

func (checkov) Supports(target Target) bool {
	return target.Type == TargetRepo || target.Type == TargetK8s
}

func (checkov) Capabilities() []Capability {
	return []Capability{{Type: model.TypeMisconfig, Targets: []TargetType{TargetRepo, TargetK8s}}}
}

func (c checkov) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	out, err := runCmd(ctx, "checkov", "-d", target.Ref, "-o", "json", "--compact", "--quiet")
	if err != nil {
		return nil, err
	}
	ver, _ := c.Version(ctx)
	return c.parse(out, ver)
}

type checkovReport struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}

type checkovCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Resource      string `json:"resource"`
	Severity      string `json:"severity"`
	Guideline     string `json:"guideline"`
}

func (c checkov) parse(data []byte, ver string) ([]model.Finding, error) {
	// Checkov emits a single object for one framework, or an array for many.
	var reports []checkovReport
	if err := json.Unmarshal(data, &reports); err != nil {
		var single checkovReport
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err // surface the array error; both failed
		}
		reports = []checkovReport{single}
	}

	var out []model.Finding
	for _, rep := range reports {
		for _, ck := range rep.Results.FailedChecks {
			start, end := lineRange(ck.FileLineRange)
			sev := severity.FromLabel(ck.Severity)
			if ck.Severity == "" {
				sev = model.SevMedium // community Checkov often omits severity
			}
			out = append(out, model.Finding{
				Type:           model.TypeMisconfig,
				Scanner:        "checkov",
				ScannerVersion: ver,
				RuleID:         ck.CheckID,
				Severity:       sev,
				Title:          firstNonEmpty(ck.CheckName, ck.CheckID),
				Description:    ck.Guideline,
				Resource:       model.Resource{Address: ck.Resource},
				Location:       model.Location{File: ck.FilePath, StartLine: start, EndLine: end},
			})
		}
	}
	return out, nil
}

func lineRange(r []int) (start, end int) {
	if len(r) >= 1 {
		start = r[0]
	}
	if len(r) >= 2 {
		end = r[1]
	}
	return
}
