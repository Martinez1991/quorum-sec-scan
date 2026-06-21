package adapter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quorum-sec/quorum/internal/model"
)

// Contract tests: parse versioned fixtures of each tool's real output. When a
// scanner changes its format, these break before production does (DESIGN §5).

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func TestTrivyParse(t *testing.T) {
	findings, err := trivy{}.parse(readFixture(t, "trivy_image.json"), "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	v := findFirst(findings, model.TypeVuln)
	if v == nil {
		t.Fatal("no VULN finding")
	}
	if v.VulnID != "CVE-2021-44228" {
		t.Errorf("VulnID = %q", v.VulnID)
	}
	if v.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("PURL = %q", v.PURL)
	}
	if v.Severity != model.SevCritical {
		t.Errorf("Severity = %q", v.Severity)
	}
	if v.CVSS != 10.0 {
		t.Errorf("CVSS = %v", v.CVSS)
	}
	if !v.Confirmed {
		t.Error("expected Confirmed (DataSource present)")
	}

	m := findFirst(findings, model.TypeMisconfig)
	if m == nil {
		t.Fatal("no MISCONFIG finding")
	}
	if m.CanonicalControl != "AVD-AWS-0086" {
		t.Errorf("CanonicalControl = %q (Trivy should pass AVD through)", m.CanonicalControl)
	}
	if m.Resource.Address != "aws_s3_bucket.data" {
		t.Errorf("Resource.Address = %q", m.Resource.Address)
	}
}

func TestGrypeParse(t *testing.T) {
	findings, err := grype{}.parse(readFixture(t, "grype_image.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.VulnID != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("VulnID = %q (raw id before alias resolution)", f.VulnID)
	}
	if len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2021-44228" {
		t.Errorf("Aliases = %v", f.Aliases)
	}
	if !f.Confirmed {
		t.Error("expected Confirmed (CVE in relatedVulnerabilities)")
	}
	if f.ScannerVersion != "0.74.0" {
		t.Errorf("version should fall back to descriptor: %q", f.ScannerVersion)
	}
}

func findFirst(fs []model.Finding, typ model.FindingType) *model.Finding {
	for i := range fs {
		if fs[i].Type == typ {
			return &fs[i]
		}
	}
	return nil
}
