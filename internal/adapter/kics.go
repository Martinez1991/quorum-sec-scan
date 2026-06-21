package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/severity"
)

func init() { Register(&kics{}) }

type kics struct{}

func (kics) Name() string { return "kics" }

func (k kics) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "kics", "version")
}

func (kics) Supports(target Target) bool {
	return target.Type == TargetRepo || target.Type == TargetK8s
}

func (kics) Capabilities() []Capability {
	return []Capability{{Type: model.TypeMisconfig, Targets: []TargetType{TargetRepo, TargetK8s}}}
}

func (k kics) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	// KICS writes a report file rather than streaming JSON to stdout, so we
	// give it a temp output dir and read the result back.
	outDir, err := os.MkdirTemp("", "quorum-kics-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.CommandContext(ctx, "kics", "scan",
		"-p", target.Ref,
		"--report-formats", "json",
		"-o", outDir,
		"--output-name", "kics",
		"--no-progress",
	)
	// KICS exits non-zero when it finds issues; that is not a failure. We rely
	// on the presence of the report file to decide success.
	runErr := cmd.Run()

	path := filepath.Join(outDir, "kics.json")
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("kics: %w", runErr)
		}
		return nil, fmt.Errorf("kics: report not produced: %w", readErr)
	}
	ver, _ := k.Version(ctx)
	return k.parse(data, ver)
}

type kicsReport struct {
	Queries []struct {
		QueryID   string `json:"query_id"`
		QueryName string `json:"query_name"`
		Severity  string `json:"severity"`
		Files     []struct {
			FileName     string `json:"file_name"`
			Line         int    `json:"line"`
			ResourceName string `json:"resource_name"`
			ResourceType string `json:"resource_type"`
			IssueType    string `json:"issue_type"`
		} `json:"files"`
	} `json:"queries"`
}

func (k kics) parse(data []byte, ver string) ([]model.Finding, error) {
	var rep kicsReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, q := range rep.Queries {
		for _, f := range q.Files {
			addr := f.ResourceType
			if f.ResourceName != "" {
				addr = f.ResourceType + "." + f.ResourceName
			}
			out = append(out, model.Finding{
				Type:           model.TypeMisconfig,
				Scanner:        "kics",
				ScannerVersion: ver,
				RuleID:         q.QueryID,
				Severity:       severity.FromLabel(q.Severity),
				Title:          firstNonEmpty(q.QueryName, q.QueryID),
				Resource:       model.Resource{Kind: f.ResourceType, Name: f.ResourceName, Address: addr},
				Location:       model.Location{File: f.FileName, StartLine: f.Line, EndLine: f.Line},
			})
		}
	}
	return out, nil
}
