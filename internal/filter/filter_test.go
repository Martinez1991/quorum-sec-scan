package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quorum-sec/quorum/internal/model"
)

func mf(fp, key string, sev model.Severity) model.MergedFinding {
	return model.MergedFinding{Fingerprint: fp, CorrelationKey: key, Severity: sev}
}

func TestApplyMinSeverity(t *testing.T) {
	in := []model.MergedFinding{
		mf("a", "k-a", model.SevCritical),
		mf("b", "k-b", model.SevMedium),
		mf("c", "k-c", model.SevLow),
	}
	r := Apply(in, model.SevHigh, &Baseline{})
	if len(r.Kept) != 1 || r.Kept[0].Fingerprint != "a" {
		t.Fatalf("kept = %+v", r.Kept)
	}
	if r.SuppressedSeverity != 2 {
		t.Errorf("SuppressedSeverity = %d, want 2", r.SuppressedSeverity)
	}
}

func TestApplyBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".quorumignore")
	content := "# accepted risks\nA1B2  # the s3 logging one\nk-c\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	bl, present, err := LoadBaseline(path)
	if err != nil || !present {
		t.Fatalf("load: present=%v err=%v", present, err)
	}
	if bl.Len() != 2 {
		t.Fatalf("baseline len = %d, want 2", bl.Len())
	}

	in := []model.MergedFinding{
		mf("a1b2", "k-a", model.SevHigh), // matched by fingerprint (case-insensitive)
		mf("zzzz", "k-c", model.SevHigh), // matched by correlationKey
		mf("keep", "k-d", model.SevHigh),
	}
	r := Apply(in, model.SevUnknown, bl)
	if len(r.Kept) != 1 || r.Kept[0].Fingerprint != "keep" {
		t.Fatalf("kept = %+v", r.Kept)
	}
	if r.SuppressedBaseline != 2 {
		t.Errorf("SuppressedBaseline = %d, want 2", r.SuppressedBaseline)
	}
}

func TestLoadBaselineMissing(t *testing.T) {
	bl, present, err := LoadBaseline(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("present should be false for missing file")
	}
	if bl.Len() != 0 {
		t.Error("missing baseline should be empty")
	}
	// Has on empty/nil baseline must be safe.
	if bl.Has(mf("x", "y", model.SevHigh)) {
		t.Error("empty baseline should not match")
	}
}
