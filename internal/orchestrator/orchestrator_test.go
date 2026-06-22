package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/model"
)

// fakeAdapter is a controllable adapter for orchestrator tests.
type fakeAdapter struct {
	name     string
	verr     error
	runErr   error
	findings []model.Finding
}

func (f *fakeAdapter) Name() string { return f.name }
func (f *fakeAdapter) Version(ctx context.Context) (string, error) {
	if f.verr != nil {
		return "", f.verr
	}
	return "1.0", nil
}
func (f *fakeAdapter) Supports(adapter.Target) bool       { return true }
func (f *fakeAdapter) Capabilities() []adapter.Capability { return nil }
func (f *fakeAdapter) Run(context.Context, adapter.Target) ([]model.Finding, error) {
	return f.findings, f.runErr
}

func vuln(scanner string) model.Finding {
	return model.Finding{
		Type: model.TypeVuln, Scanner: scanner, VulnID: "CVE-2021-44228",
		PURL:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Severity: model.SevCritical, Title: "log4shell",
	}
}

func init() {
	adapter.Register(&fakeAdapter{name: "fakea", findings: []model.Finding{vuln("fakea")}})
	adapter.Register(&fakeAdapter{name: "fakeb", findings: []model.Finding{vuln("fakeb")}})
	adapter.Register(&fakeAdapter{name: "fakedown", verr: errors.New("not installed")})
	adapter.Register(&fakeAdapter{name: "fakeboom", runErr: errors.New("boom")})
}

func TestOrchestratorMergesAcrossScanners(t *testing.T) {
	res, err := Run(context.Background(), adapter.Target{Type: adapter.TargetImage, Ref: "x"}, Options{
		Scanners: []string{"fakea", "fakeb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Merged) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(res.Merged))
	}
	if res.Merged[0].DetectionCount != 2 {
		t.Errorf("DetectionCount = %d, want 2 (fakea+fakeb)", res.Merged[0].DetectionCount)
	}
	for _, r := range res.Runs {
		if r.Status != "ran" {
			t.Errorf("%s status = %q, want ran", r.Name, r.Status)
		}
	}
}

func TestOrchestratorReportsUnavailableAndError(t *testing.T) {
	res, err := Run(context.Background(), adapter.Target{Type: adapter.TargetImage, Ref: "x"}, Options{
		Scanners: []string{"fakedown", "fakeboom"},
	})
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range res.Runs {
		status[r.Name] = r.Status
	}
	if status["fakedown"] != "unavailable" {
		t.Errorf("fakedown status = %q, want unavailable", status["fakedown"])
	}
	if status["fakeboom"] != "error" {
		t.Errorf("fakeboom status = %q, want error", status["fakeboom"])
	}
	if len(res.Merged) != 0 {
		t.Errorf("want 0 findings, got %d", len(res.Merged))
	}
}

func TestSelectUnknownScannerIgnored(t *testing.T) {
	res, err := Run(context.Background(), adapter.Target{Type: adapter.TargetImage, Ref: "x"}, Options{
		Scanners: []string{"does-not-exist"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runs) != 0 {
		t.Errorf("unknown scanner should yield no runs, got %d", len(res.Runs))
	}
}
