package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quorum-sec/quorum/internal/orchestrator"
	"github.com/quorum-sec/quorum/internal/report"
	"github.com/spf13/cobra"
)

func TestValidateTargetRef(t *testing.T) {
	for _, good := range []string{".", "./x", "myimage:1.2.3", "/work", "registry.io/app:tag"} {
		if err := validateTargetRef(good); err != nil {
			t.Errorf("validateTargetRef(%q) = %v, want nil", good, err)
		}
	}
	for _, bad := range []string{"-rf", "--config=/etc/x", "-"} {
		if err := validateTargetRef(bad); err == nil {
			t.Errorf("validateTargetRef(%q) = nil, want error (argument injection)", bad)
		}
	}
}

func TestEmitCleansOutputPath(t *testing.T) {
	dir := t.TempDir()
	// A path with a ../ segment must be normalized before writing.
	out := filepath.Join(dir, "sub", "..", "report.json")
	want := filepath.Join(dir, "report.json")

	format, err := report.ParseFormat("json")
	if err != nil {
		t.Fatal(err)
	}
	if err := emit(&cobra.Command{}, &orchestrator.Result{}, format, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected report at cleaned path %q: %v", want, err)
	}
}

func TestResolveCrosswalkDir(t *testing.T) {
	existing := t.TempDir()
	missing := filepath.Join(existing, "does-not-exist")

	t.Run("explicit flag is respected verbatim even if missing", func(t *testing.T) {
		if got := resolveCrosswalkDir(missing, true); got != missing {
			t.Fatalf("got %q, want %q", got, missing)
		}
	})

	t.Run("default dir used when it exists", func(t *testing.T) {
		if got := resolveCrosswalkDir(existing, false); got != existing {
			t.Fatalf("got %q, want %q", got, existing)
		}
	})

	t.Run("falls back to bundled dir when default missing", func(t *testing.T) {
		// Only meaningful where the bundled dir actually exists (the Docker image).
		if !isDir(bundledCrosswalkDir) {
			t.Skipf("%s not present in this environment", bundledCrosswalkDir)
		}
		if got := resolveCrosswalkDir(missing, false); got != bundledCrosswalkDir {
			t.Fatalf("got %q, want %q", got, bundledCrosswalkDir)
		}
	})

	t.Run("returns original when neither default nor bundle exist", func(t *testing.T) {
		if isDir(bundledCrosswalkDir) {
			t.Skip("bundled dir present; fallback would trigger")
		}
		if got := resolveCrosswalkDir(missing, false); got != missing {
			t.Fatalf("got %q, want %q", got, missing)
		}
	})
}

func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	if !isDir(dir) {
		t.Fatalf("expected %q to be a dir", dir)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isDir(file) {
		t.Fatalf("expected %q (a file) not to be a dir", file)
	}
	if isDir(filepath.Join(dir, "nope")) {
		t.Fatalf("expected missing path not to be a dir")
	}
}
