package cache

import (
	"path/filepath"
	"testing"
)

func TestStorePutGetPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "aliases.json")

	s := Open(path) // parent dir does not exist yet; Put must create it
	if _, ok := s.Get("GHSA-x"); ok {
		t.Fatal("empty store should miss")
	}
	s.Put("GHSA-x", "CVE-1")
	if v, ok := s.Get("GHSA-x"); !ok || v != "CVE-1" {
		t.Fatalf("Get = %q,%v", v, ok)
	}

	// Reopen from disk: the value must persist.
	s2 := Open(path)
	if v, ok := s2.Get("GHSA-x"); !ok || v != "CVE-1" {
		t.Fatalf("persisted Get = %q,%v", v, ok)
	}
	if s2.Len() != 1 {
		t.Errorf("Len = %d, want 1", s2.Len())
	}
}

func TestStoreNilAndEmptyPathSafe(t *testing.T) {
	var s *Store
	s.Put("a", "b") // must not panic on nil
	if _, ok := s.Get("a"); ok {
		t.Error("nil store should miss")
	}

	mem := Open("") // empty path = in-memory only, no disk
	mem.Put("a", "b")
	if v, ok := mem.Get("a"); !ok || v != "b" {
		t.Fatalf("in-memory Get = %q,%v", v, ok)
	}
}
