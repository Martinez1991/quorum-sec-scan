package correlate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quorum-sec/quorum/internal/alias"
	"github.com/quorum-sec/quorum/internal/cache"
	"github.com/quorum-sec/quorum/internal/consensus"
	"github.com/quorum-sec/quorum/internal/correlate"
	"github.com/quorum-sec/quorum/internal/crosswalk"
	"github.com/quorum-sec/quorum/internal/model"
)

// TestMVPConsensus is the DESIGN roadmap "done" criterion for the MVP: Trivy
// reports a CVE and Grype reports the equivalent GHSA; after alias resolution
// they must collapse into ONE finding with detectionCount 2.
func TestMVPConsensus(t *testing.T) {
	trivyF := model.Finding{
		Type: model.TypeVuln, Scanner: "trivy", VulnID: "CVE-2021-44228",
		PURL:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Severity: model.SevCritical, CVSS: 10.0, Confirmed: true,
		Title: "Log4Shell",
	}
	grypeF := model.Finding{
		Type: model.TypeVuln, Scanner: "grype", VulnID: "GHSA-jfh8-c2jp-5v3q",
		Aliases:  []string{"CVE-2021-44228"},
		PURL:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Severity: model.SevCritical, CVSS: 10.0, Confirmed: true,
	}

	// Offline resolver: no OSV, relies on the finding-local alias. The GHSA must
	// still canonicalize to the CVE so the keys match.
	c := correlate.New(alias.New(cache.Open(""), nil), crosswalk.New())
	enriched := c.Enrich(context.Background(), []model.Finding{trivyF, grypeF})

	if enriched[1].VulnID != "CVE-2021-44228" {
		t.Fatalf("grype GHSA not canonicalized to CVE: got %q", enriched[1].VulnID)
	}
	if enriched[0].CorrelationKey != enriched[1].CorrelationKey {
		t.Fatalf("keys differ:\n  %s\n  %s", enriched[0].CorrelationKey, enriched[1].CorrelationKey)
	}

	merged := consensus.Merge(enriched)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(merged))
	}
	m := merged[0]
	if m.DetectionCount != 2 {
		t.Errorf("DetectionCount = %d, want 2", m.DetectionCount)
	}
	if len(m.DetectedBy) != 2 {
		t.Errorf("DetectedBy = %v", m.DetectedBy)
	}
	if m.Severity != model.SevCritical {
		t.Errorf("Severity = %q", m.Severity)
	}
	if m.Confidence <= 0 || m.Confidence > 1 {
		t.Errorf("Confidence out of range: %v", m.Confidence)
	}
}

// TestFalseSplitPreferred: two MISCONFIG findings whose canonical control could
// not be resolved must NOT merge (DESIGN §3: false split > false merge).
func TestUnmappedNeverMerges(t *testing.T) {
	a := model.Finding{Type: model.TypeMisconfig, Scanner: "checkov", RuleID: "CKV_AWS_999",
		Location: model.Location{File: "main.tf"}, Resource: model.Resource{Address: "aws_s3_bucket.x"}}
	b := model.Finding{Type: model.TypeMisconfig, Scanner: "kics", RuleID: "uuid-zzz",
		Location: model.Location{File: "main.tf"}, Resource: model.Resource{Address: "aws_s3_bucket.x"}}

	c := correlate.New(alias.New(cache.Open(""), nil), crosswalk.New()) // empty crosswalk
	enriched := c.Enrich(context.Background(), []model.Finding{a, b})
	if !enriched[0].Unmapped || !enriched[1].Unmapped {
		t.Fatal("expected both findings flagged unmapped")
	}
	merged := consensus.Merge(enriched)
	if len(merged) != 2 {
		t.Fatalf("unmapped findings from different scanners must not merge: got %d groups", len(merged))
	}
}

// TestCrosswalkMerges: with a crosswalk mapping both engines' rules to the same
// canonical control, equivalent misconfigs DO merge.
func TestCrosswalkMerges(t *testing.T) {
	cw := crosswalk.New()
	loadInline(t, cw)

	checkovF := model.Finding{Type: model.TypeMisconfig, Scanner: "checkov", RuleID: "CKV_AWS_20",
		Location: model.Location{File: "./main.tf"}, Resource: model.Resource{Address: "aws_s3_bucket.data"}}
	trivyF := model.Finding{Type: model.TypeMisconfig, Scanner: "trivy", CanonicalControl: "AVD-AWS-0091",
		Location: model.Location{File: "main.tf"}, Resource: model.Resource{Address: "aws_s3_bucket.data"}}

	c := correlate.New(nil, cw)
	enriched := c.Enrich(context.Background(), []model.Finding{checkovF, trivyF})
	merged := consensus.Merge(enriched)
	if len(merged) != 1 {
		t.Fatalf("checkov+trivy S3 misconfig should merge via crosswalk: got %d groups\n  %s\n  %s",
			len(merged), enriched[0].CorrelationKey, enriched[1].CorrelationKey)
	}
	if merged[0].DetectionCount != 2 {
		t.Errorf("DetectionCount = %d", merged[0].DetectionCount)
	}
}

func loadInline(t *testing.T, cw *crosswalk.Crosswalk) {
	t.Helper()
	// Use the real loader against a temp file so the YAML format is exercised.
	dir := t.TempDir()
	const y = `
- canonicalControl: AVD-AWS-0091
  category: public-access
  ids:
    checkov: [CKV_AWS_20]
    trivy:   [AVD-AWS-0091]
`
	if err := os.WriteFile(filepath.Join(dir, "aws.yaml"), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := crosswalk.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	*cw = *loaded
}
