package adapter

import (
	"context"
	"encoding/json"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/severity"
)

func init() { Register(&dockle{}) }

type dockle struct{}

func (dockle) Name() string { return "dockle" }

func (d dockle) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "dockle", "--version")
}

func (dockle) Supports(target Target) bool { return target.Type == TargetImage }

func (dockle) Capabilities() []Capability {
	return []Capability{{Type: model.TypeImgHardening, Targets: []TargetType{TargetImage}}}
}

func (d dockle) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	// --exit-code 0 so a clean image vs. findings is distinguished by content,
	// not exit status.
	out, err := runCmd(ctx, "dockle", "-f", "json", "--exit-code", "0", target.Ref)
	if err != nil {
		return nil, err
	}
	ver, _ := d.Version(ctx)
	return d.parse(out, ver)
}

type dockleReport struct {
	Details []struct {
		Code   string   `json:"code"`
		Title  string   `json:"title"`
		Level  string   `json:"level"`
		Alerts []string `json:"alerts"`
	} `json:"details"`
}

func (d dockle) parse(data []byte, ver string) ([]model.Finding, error) {
	var rep dockleReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, det := range rep.Details {
		lvl := severity.FromDockle(det.Level)
		if lvl == model.SevInfo || det.Level == "PASS" || det.Level == "IGNORE" || det.Level == "SKIP" {
			continue // only emit actionable hardening gaps
		}
		desc := ""
		if len(det.Alerts) > 0 {
			desc = det.Alerts[0]
		}
		out = append(out, model.Finding{
			Type:             model.TypeImgHardening,
			Scanner:          "dockle",
			ScannerVersion:   ver,
			RuleID:           det.Code,
			CanonicalControl: det.Code, // CIS-DI id is already canonical
			Severity:         lvl,
			Title:            firstNonEmpty(det.Title, det.Code),
			Description:      desc,
		})
	}
	return out, nil
}
