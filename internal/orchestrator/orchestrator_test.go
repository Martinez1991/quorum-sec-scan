package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quorum-sec/quorum/internal/adapter"
	"github.com/quorum-sec/quorum/internal/model"
)

// fakeAdapter is a controllable adapter for orchestrator tests.
type fakeAdapter struct {
	name     string
	verr     error
	vblock   bool // Version blocks until ctx is cancelled (simulates a slow probe)
	runErr   error
	findings []model.Finding
}

func (f *fakeAdapter) Name() string { return f.name }
func (f *fakeAdapter) Version(ctx context.Context) (string, error) {
	if f.vblock {
		<-ctx.Done()
		return "", ctx.Err()
	}
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
	adapter.Register(&fakeAdapter{name: "fakeslow", vblock: true})
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
	var logs []string
	res, err := Run(context.Background(), adapter.Target{Type: adapter.TargetImage, Ref: "x"}, Options{
		Scanners: []string{"does-not-exist", "fakea"},
		Logf:     func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The unknown name is dropped (only the known one runs)...
	if len(res.Runs) != 1 || res.Runs[0].Name != "fakea" {
		t.Errorf("want only fakea to run, got %+v", res.Runs)
	}
	// ...but it must be surfaced as a warning, not silently swallowed.
	var warned bool
	for _, l := range logs {
		if strings.Contains(l, "unknown scanner") && strings.Contains(l, "does-not-exist") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a warning about the unknown scanner; logs=%v", logs)
	}
}

func TestProbeTimeoutMarksUnavailable(t *testing.T) {
	var logs []string
	res, err := Run(context.Background(), adapter.Target{Type: adapter.TargetImage, Ref: "x"}, Options{
		Scanners:  []string{"fakeslow"},
		ProbeTime: 50 * time.Millisecond,
		Logf:      func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runs) != 1 || res.Runs[0].Status != "unavailable" {
		t.Fatalf("want fakeslow unavailable, got %+v", res.Runs)
	}
	if !strings.Contains(res.Runs[0].Error, "version probe exceeded") {
		t.Errorf("want a clear probe-timeout error, got %q", res.Runs[0].Error)
	}
	var sawTimeoutLog bool
	for _, l := range logs {
		if strings.Contains(l, "fakeslow") && strings.Contains(l, "timed out") {
			sawTimeoutLog = true
		}
	}
	if !sawTimeoutLog {
		t.Errorf("expected a probe-timeout log line; logs=%v", logs)
	}
}
