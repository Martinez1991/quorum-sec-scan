package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/orchestrator"
)

func sampleResult() *orchestrator.Result {
	return &orchestrator.Result{
		Target: adapter.Target{Type: adapter.TargetRepo, Ref: "."},
		Runs: []orchestrator.ScannerRun{
			{Name: "trivy", Status: "ran", Findings: 1, Version: "0.55.0"},
			{Name: "checkov", Status: "ran", Findings: 1, Version: "3.2"},
		},
		Merged: []model.MergedFinding{{
			CorrelationKey: "MISCONFIG|main.tf|aws_s3_bucket.data|AVD-AWS-0086",
			Type:           model.TypeMisconfig,
			Title:          "S3 bucket without public-access block",
			Severity:       model.SevHigh,
			DetectedBy:     []string{"checkov", "trivy"},
			DetectionCount: 2,
			Confidence:     0.81,
			Fingerprint:    "abc123",
			Members: []model.Finding{
				{Scanner: "trivy", CanonicalControl: "AVD-AWS-0086", Location: model.Location{File: "main.tf", StartLine: 1, EndLine: 3}},
				{Scanner: "checkov", RuleID: "CKV_AWS_53", Location: model.Location{File: "main.tf", StartLine: 1}},
			},
		}},
	}
}

func TestSARIFOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult(), FormatSARIF); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"sarif-schema-2.1.0", "AVD-AWS-0086", "quorum/v1", "abc123",
		"detectionCount", "\"level\": \"error\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF missing %q", want)
		}
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary struct {
			TotalFindings int `json:"totalFindings"`
			MultiDetected int `json:"multiDetected"`
		} `json:"summary"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.TotalFindings != 1 || doc.Summary.MultiDetected != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(doc.Findings))
	}
}

func TestXMLOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult(), FormatXML); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<?xml") {
		t.Error("missing XML header")
	}
	for _, want := range []string{"quorumReport", "detectionCount=\"2\"", "AVD-AWS-0086"} {
		if !strings.Contains(out, want) {
			t.Errorf("XML missing %q", want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, f := range []string{"sarif", "json", "xml", "SARIF"} {
		if _, err := ParseFormat(f); err != nil {
			t.Errorf("ParseFormat(%q): %v", f, err)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Error("pdf should be rejected")
	}
}
