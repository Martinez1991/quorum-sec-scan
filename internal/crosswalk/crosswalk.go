// Package crosswalk maps each scanner's own rule ids to a shared canonical
// control (AVD hub, with a semantic category fallback) so equivalent IaC/k8s
// misconfigs from different engines correlate (DESIGN §8).
package crosswalk

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Control is one canonical control grouping equivalent rule ids across scanners.
type Control struct {
	CanonicalControl string              `yaml:"canonicalControl"`
	Category         string              `yaml:"category"`
	CWE              string              `yaml:"cwe"`
	Title            string              `yaml:"title"`
	IDs              map[string][]string `yaml:"ids"` // scanner -> []ruleID
}

// Resolution is what Resolve returns for a matched rule.
type Resolution struct {
	Control  string
	Category string
	CWE      string
	Title    string
}

// Crosswalk is the loaded, indexed mapping.
type Crosswalk struct {
	// byRule indexes "scanner|ruleID" (lowercased) -> Resolution.
	byRule map[string]Resolution
}

// New returns an empty crosswalk (every lookup misses → findings stay unmapped).
func New() *Crosswalk {
	return &Crosswalk{byRule: map[string]Resolution{}}
}

// Load reads every *.yaml/*.yml file under dir and merges them. A missing dir
// is not an error (the tool runs with no custom crosswalk).
func Load(dir string) (*Crosswalk, error) {
	cw := New()
	if dir == "" {
		return cw, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return cw, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var controls []Control
		if err := yaml.Unmarshal(b, &controls); err != nil {
			return nil, err
		}
		cw.add(controls)
	}
	return cw, nil
}

func (c *Crosswalk) add(controls []Control) {
	for _, ctrl := range controls {
		res := Resolution{
			Control:  ctrl.CanonicalControl,
			Category: ctrl.Category,
			CWE:      ctrl.CWE,
			Title:    ctrl.Title,
		}
		for scanner, ids := range ctrl.IDs {
			for _, id := range ids {
				c.byRule[key(scanner, id)] = res
			}
		}
	}
}

// Resolve looks up a scanner rule id. ok=false means no mapping was found and
// the caller must keep the finding isolated and flag it unmapped (DESIGN §6
// "never guess a match").
func (c *Crosswalk) Resolve(scanner, ruleID string) (Resolution, bool) {
	r, ok := c.byRule[key(scanner, ruleID)]
	return r, ok
}

// Len reports the number of indexed rule ids.
func (c *Crosswalk) Len() int { return len(c.byRule) }

func key(scanner, ruleID string) string {
	return strings.ToLower(strings.TrimSpace(scanner)) + "|" + strings.TrimSpace(ruleID)
}
