package alias

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quorum-sec/quorum/internal/cache"
)

func TestOSVClientAliases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vulns/GHSA-jfh8-c2jp-5v3q" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"id":"GHSA-jfh8-c2jp-5v3q","aliases":["CVE-2021-44228"],"related":["CVE-2021-45046"]}`))
	}))
	defer srv.Close()

	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}
	got, err := c.Aliases(context.Background(), "GHSA-jfh8-c2jp-5v3q")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(got, "CVE-2021-44228") || !contains(got, "GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("aliases = %v", got)
	}
}

func TestOSVClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Aliases(context.Background(), "X"); err == nil {
		t.Error("expected error on 500")
	}
}

func TestOSVRejectsMalformedID(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()
	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client()}

	for _, bad := range []string{"../../etc/passwd", "CVE-1/../x", "a b", "?q=1", "", "-CVE-1"} {
		if _, err := c.Aliases(context.Background(), bad); err == nil {
			t.Errorf("expected error for malformed id %q", bad)
		}
	}
	if hits != 0 {
		t.Errorf("malformed ids must not reach the network; got %d request(s)", hits)
	}

	// A well-formed id is still accepted (reaches the server).
	if _, err := c.Aliases(context.Background(), "CVE-2021-44228"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	if hits == 0 {
		t.Error("valid id should have reached the server")
	}
}

func TestOSVClientRetries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) <= 2 {
			http.Error(w, "transient", http.StatusServiceUnavailable) // 503: retryable
			return
		}
		w.Write([]byte(`{"id":"GHSA-x","aliases":["CVE-7777-1"]}`))
	}))
	defer srv.Close()
	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client(), MaxRetries: 3, Backoff: time.Millisecond}
	got, err := c.Aliases(context.Background(), "GHSA-x")
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if !contains(got, "CVE-7777-1") {
		t.Errorf("aliases = %v", got)
	}
	if hits != 3 {
		t.Errorf("server hit %d times, want 3 (2 failures + 1 success)", hits)
	}
}

func TestOSVClientNoRetryOn404(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r) // 404: not retryable
	}))
	defer srv.Close()
	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client(), MaxRetries: 3, Backoff: time.Millisecond}
	if _, err := c.Aliases(context.Background(), "X"); err == nil {
		t.Error("expected error")
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (404 is not retried)", hits)
	}
}

// stubOSV implements osvSource and counts calls.
type stubOSV struct {
	aliases []string
	err     error
	calls   int32
}

func (s *stubOSV) Aliases(ctx context.Context, id string) ([]string, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.aliases, s.err
}

func TestResolverPrefersLocalAliases(t *testing.T) {
	// A CVE already present in the finding's own aliases needs no network.
	stub := &stubOSV{}
	r := New(cache.Open(""), stub)
	got := r.Canonical(context.Background(), "GHSA-x", []string{"CVE-2021-44228"})
	if got != "CVE-2021-44228" {
		t.Errorf("got %q, want CVE-2021-44228", got)
	}
	if stub.calls != 0 {
		t.Errorf("OSV called %d times, want 0 (local aliases sufficed)", stub.calls)
	}
}

func TestResolverUsesOSVThenCaches(t *testing.T) {
	store := cache.Open("")
	stub := &stubOSV{aliases: []string{"GHSA-x", "CVE-9999-1"}}
	r := New(store, stub)

	got := r.Canonical(context.Background(), "GHSA-x", nil)
	if got != "CVE-9999-1" {
		t.Fatalf("got %q, want CVE-9999-1", got)
	}
	// Second call must hit the cache, not OSV again.
	_ = r.Canonical(context.Background(), "GHSA-x", nil)
	if stub.calls != 1 {
		t.Errorf("OSV called %d times, want 1 (second resolved from cache)", stub.calls)
	}
}

func TestResolverDegradesOnError(t *testing.T) {
	r := New(cache.Open(""), &stubOSV{err: context.DeadlineExceeded})
	got := r.Canonical(context.Background(), "GHSA-only", nil)
	if got != "GHSA-only" {
		t.Errorf("got %q, want the id unchanged on network failure", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
