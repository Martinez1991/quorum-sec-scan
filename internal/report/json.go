package report

import (
	"encoding/json"
	"io"

	"github.com/quorum-sec/quorum/internal/orchestrator"
)

// jsonReport is the stable shape of the JSON output: the scanner run summary
// plus the merged, scored findings (a direct dump of []MergedFinding).
type jsonReport struct {
	Tool     string                    `json:"tool"`
	Version  string                    `json:"version"`
	Target   targetJSON                `json:"target"`
	Scanners []orchestrator.ScannerRun `json:"scanners"`
	Summary  summaryJSON               `json:"summary"`
	Findings any                       `json:"findings"`
}

type targetJSON struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
}

type summaryJSON struct {
	TotalFindings  int            `json:"totalFindings"`
	DurationMillis int64          `json:"durationMs"`
	BySeverity     map[string]int `json:"bySeverity"`
	MultiDetected  int            `json:"multiDetected"` // findings with detectionCount > 1
}

func writeJSON(w io.Writer, res *orchestrator.Result) error {
	bySev := map[string]int{}
	multi := 0
	for _, m := range res.Merged {
		bySev[string(m.Severity)]++
		if m.DetectionCount > 1 {
			multi++
		}
	}
	rep := jsonReport{
		Tool:     "quorum",
		Version:  Version,
		Target:   targetJSON{Type: string(res.Target.Type), Ref: res.Target.Ref},
		Scanners: res.Runs,
		Summary: summaryJSON{
			TotalFindings:  len(res.Merged),
			DurationMillis: res.Duration.Milliseconds(),
			BySeverity:     bySev,
			MultiDetected:  multi,
		},
		Findings: res.Merged,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
