package adapter

import (
	"context"
	"testing"

	"github.com/quorum-sec/quorum/internal/alias"
	"github.com/quorum-sec/quorum/internal/cache"
	"github.com/quorum-sec/quorum/internal/consensus"
	"github.com/quorum-sec/quorum/internal/correlate"
	"github.com/quorum-sec/quorum/internal/crosswalk"
	"github.com/quorum-sec/quorum/internal/model"
)

// These tests parse REAL scanner output (captured from Trivy/Checkov/KICS/Grype
// run via their official Docker images against examples/terraform and
// alpine:3.10) and drive it through the real correlation + crosswalk + consensus
// pipeline. They are the proof that consensus actually happens on real data, and
// they break if a tool's output format drifts.

// loadRealCrosswalk loads the repo's shipped crosswalk (../../crosswalk).
func loadRealCrosswalk(t *testing.T) *crosswalk.Crosswalk {
	t.Helper()
	cw, err := crosswalk.Load("../../crosswalk")
	if err != nil {
		t.Fatalf("load crosswalk: %v", err)
	}
	if cw.Len() == 0 {
		t.Fatal("crosswalk loaded 0 rules")
	}
	return cw
}

// offlineCorrelator: real crosswalk, alias resolver with no network (relies on
// finding-local aliases — enough for OS-package CVEs that match directly).
func offlineCorrelator(t *testing.T) *correlate.Correlator {
	return correlate.New(alias.New(cache.Open(""), nil), loadRealCrosswalk(t))
}

func TestRealParse_Counts(t *testing.T) {
	cases := []struct {
		name    string
		parse   func() ([]model.Finding, error)
		want    int
		wantTyp model.FindingType
	}{
		{"trivy-iac", func() ([]model.Finding, error) { return trivy{}.parse(readFixture(t, "iac_trivy.json"), "x") }, 12, model.TypeMisconfig},
		{"checkov-iac", func() ([]model.Finding, error) { return checkov{}.parse(readFixture(t, "iac_checkov.json"), "x") }, 17, model.TypeMisconfig},
		{"kics-iac", func() ([]model.Finding, error) { return kics{}.parse(readFixture(t, "iac_kics.json"), "x") }, 9, model.TypeMisconfig},
		{"trivy-sca", func() ([]model.Finding, error) { return trivy{}.parse(readFixture(t, "sca_trivy_alpine.json"), "x") }, 1, model.TypeVuln},
		{"grype-sca", func() ([]model.Finding, error) { return grype{}.parse(readFixture(t, "sca_grype_alpine.json"), "x") }, 1, model.TypeVuln},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := c.parse()
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != c.want {
				t.Fatalf("got %d findings, want %d", len(fs), c.want)
			}
			for _, f := range fs {
				if f.Type != c.wantTyp {
					t.Errorf("finding type = %q, want %q", f.Type, c.wantTyp)
				}
				if f.Scanner == "" || f.Title == "" {
					t.Errorf("finding missing scanner/title: %+v", f)
				}
			}
		})
	}
}

// TestRealIaCConsensus: Trivy + Checkov + KICS over the same Terraform must
// reach 3-way consensus on the controls that all three engines cover, after
// the crosswalk reconciles their differing rule ids, file paths and resource
// identities.
func TestRealIaCConsensus(t *testing.T) {
	var all []model.Finding
	for name, parse := range map[string]func([]byte, string) ([]model.Finding, error){
		"iac_trivy.json":   func(b []byte, v string) ([]model.Finding, error) { return trivy{}.parse(b, v) },
		"iac_checkov.json": func(b []byte, v string) ([]model.Finding, error) { return checkov{}.parse(b, v) },
		"iac_kics.json":    func(b []byte, v string) ([]model.Finding, error) { return kics{}.parse(b, v) },
	} {
		fs, err := parse(readFixture(t, name), "x")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all = append(all, fs...)
	}

	merged := consensus.Merge(offlineCorrelator(t).Enrich(context.Background(), all))
	byControl := indexByControl(merged)

	// Controls all three engines detect → detectionCount 3.
	for _, ctrl := range []string{"AVD-AWS-0090", "AVD-AWS-0089", "AVD-AWS-0092", "AVD-AWS-0057"} {
		m, ok := byControl[ctrl]
		if !ok {
			t.Errorf("%s: not present in merged output", ctrl)
			continue
		}
		if m.DetectionCount != 3 {
			t.Errorf("%s: detectionCount = %d (%v), want 3", ctrl, m.DetectionCount, m.DetectedBy)
		}
	}

	// Control only Trivy + Checkov cover → detectionCount 2.
	if m, ok := byControl["AVD-AWS-0132"]; !ok {
		t.Error("AVD-AWS-0132 missing")
	} else if m.DetectionCount != 2 {
		t.Errorf("AVD-AWS-0132: detectionCount = %d (%v), want 2", m.DetectionCount, m.DetectedBy)
	}
}

// TestRealSCAConsensus: the real MVP criterion — Trivy and Grype agree on
// CVE-2021-36159 in apk-tools (same package) → one finding, detectionCount 2.
func TestRealSCAConsensus(t *testing.T) {
	tf, err := trivy{}.parse(readFixture(t, "sca_trivy_alpine.json"), "x")
	if err != nil {
		t.Fatal(err)
	}
	gf, err := grype{}.parse(readFixture(t, "sca_grype_alpine.json"), "x")
	if err != nil {
		t.Fatal(err)
	}

	merged := consensus.Merge(offlineCorrelator(t).Enrich(context.Background(), append(tf, gf...)))

	var found *model.MergedFinding
	for i := range merged {
		if len(merged[i].Members) > 0 && merged[i].Members[0].VulnID == "CVE-2021-36159" {
			found = &merged[i]
			break
		}
	}
	if found == nil {
		t.Fatal("CVE-2021-36159 not in merged output")
	}
	if found.DetectionCount != 2 {
		t.Errorf("CVE-2021-36159: detectionCount = %d (%v), want 2", found.DetectionCount, found.DetectedBy)
	}
	if found.Severity != model.SevCritical {
		t.Errorf("severity = %q, want CRITICAL", found.Severity)
	}
}

func indexByControl(merged []model.MergedFinding) map[string]model.MergedFinding {
	out := map[string]model.MergedFinding{}
	for _, m := range merged {
		if len(m.Members) > 0 && m.Members[0].CanonicalControl != "" {
			out[m.Members[0].CanonicalControl] = m
		}
	}
	return out
}
