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
	BaseURL string
	HTTP    *http.Client
}

// NewOSVClient returns a client with sane CI defaults.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL: "https://api.osv.dev",
		HTTP:    &http.Client{Timeout: 8 * time.Second},
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: %s -> %s", id, resp.Status)
	}
	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	out := append([]string{v.ID}, v.Aliases...)
	out = append(out, v.Related...)
	return out, nil
}
