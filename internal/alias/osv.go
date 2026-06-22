package alias

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OSVClient queries OSV.dev to resolve a vuln id to its alias set. It is the
// arbiter of last resort in the resolver chain.
type OSVClient struct {
	BaseURL    string
	HTTP       *http.Client
	MaxRetries int           // additional attempts on transient failure (default 2)
	Backoff    time.Duration // base backoff between attempts (default 200ms)
}

// NewOSVClient returns a client with sane CI defaults.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL:    "https://api.osv.dev",
		HTTP:       &http.Client{Timeout: 8 * time.Second},
		MaxRetries: 2,
		Backoff:    200 * time.Millisecond,
	}
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Related  []string `json:"related"`
	Upstream []string `json:"upstream"`
}

// Aliases returns the alias ids OSV knows for id (including id itself). A
// network/HTTP failure is returned as an error so the caller can degrade
// gracefully (DESIGN §7: never fail the whole scan over alias lookup).
func (c *OSVClient) Aliases(ctx context.Context, id string) ([]string, error) {
	if c == nil {
		return nil, fmt.Errorf("nil osv client")
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/v1/vulns/" + id

	attempts := c.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, c.Backoff*time.Duration(1<<(attempt-1))); err != nil {
				return nil, err
			}
		}
		v, retryable, err := c.fetch(ctx, url, id)
		if err == nil {
			out := append([]string{v.ID}, v.Aliases...)
			return append(out, v.Related...), nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// fetch does one request. retryable is true for transient failures (network
// errors, 429, 5xx) the caller should back off and retry.
func (c *OSVClient) fetch(ctx context.Context, url, id string) (osvVuln, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return osvVuln{}, false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return osvVuln{}, true, err // network error: retryable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return osvVuln{}, retryable, fmt.Errorf("osv: %s -> %s", id, resp.Status)
	}
	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return osvVuln{}, false, err
	}
	return v, false, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
