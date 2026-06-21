// Package cache is a tiny persistent key/value store backed by a JSON file.
// It gives the alias resolver idempotency and speed across CI re-scans without
// pulling in a CGO database. Safe for concurrent use within a process.
package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Store is an in-memory map flushed to disk on Put.
type Store struct {
	mu   sync.RWMutex
	path string
	data map[string]string
}

// Open loads the cache at path (creating parent dirs lazily on first Put). A
// missing or unreadable file yields an empty cache rather than an error, so a
// bad cache never breaks a scan.
func Open(path string) *Store {
	s := &Store{path: path, data: map[string]string{}}
	if path == "" {
		return s
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

// Get returns the cached value for key.
func (s *Store) Get(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}

// Put stores key=value and flushes to disk. Flush errors are intentionally
// swallowed: the cache is an optimization, never a source of scan failure.
func (s *Store) Put(key, value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.data[key] = value
	path := s.path
	snapshot := make(map[string]string, len(s.data))
	for k, v := range s.data {
		snapshot[k] = v
	}
	s.mu.Unlock()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	if b, err := json.MarshalIndent(snapshot, "", "  "); err == nil {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			_ = os.Rename(tmp, path)
		}
	}
}

// Len reports how many entries are cached.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}
