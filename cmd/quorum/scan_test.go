package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
