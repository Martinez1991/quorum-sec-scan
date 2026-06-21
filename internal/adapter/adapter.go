// Package adapter wraps each external scanner CLI and translates its native
// output into canonical model.Finding values. Adding a scanner = adding an
// adapter here; nothing in the core changes.
package adapter

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
)

// TargetType enumerates what kind of artifact is being scanned.
type TargetType string

const (
	TargetImage TargetType = "image" // container image ref
	TargetRepo  TargetType = "repo"  // filesystem path (repo / IaC / manifests)
	TargetK8s   TargetType = "k8s"   // k8s manifests path or live cluster
)

// Target is the thing being scanned.
type Target struct {
	Type TargetType
	Ref  string // image reference or filesystem path
}

// Capability advertises what a scanner produces and for which targets.
type Capability struct {
	Type    model.FindingType
	Targets []TargetType
}

// Adapter is the contract every scanner integration implements.
type Adapter interface {
	Name() string
	// Version returns the installed tool version, or an error if the binary
	// is missing/unrunnable (used to skip unavailable scanners).
	Version(ctx context.Context) (string, error)
	// Supports reports whether this adapter can scan the given target.
	Supports(target Target) bool
	// Capabilities describes the finding types/targets this adapter covers.
	Capabilities() []Capability
	// Run invokes the tool and translates its output into canonical findings.
	Run(ctx context.Context, target Target) ([]model.Finding, error)
}

// Registry holds the known adapters keyed by name.
var registry = map[string]Adapter{}

// Register makes an adapter discoverable by name. Called from each adapter's
// init(). Panics on duplicate name (programming error).
func Register(a Adapter) {
	name := a.Name()
	if _, dup := registry[name]; dup {
		panic("adapter: duplicate registration for " + name)
	}
	registry[name] = a
}

// Get returns an adapter by name.
func Get(name string) (Adapter, bool) {
	a, ok := registry[strings.ToLower(name)]
	return a, ok
}

// All returns every registered adapter.
func All() []Adapter {
	out := make([]Adapter, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	return out
}

// Names returns the registered adapter names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// runCmd executes bin with args, returning stdout. stderr is folded into the
// error so adapters can surface why a tool failed. A non-zero exit is only an
// error when stdout is empty — several scanners exit non-zero precisely
// because they found issues (that is a successful scan, not a failure).
func runCmd(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		// Non-zero exit but produced output: treat as success (findings-found convention).
	}
	return stdout.Bytes(), nil
}

// toolVersion runs `bin <args...>` and returns the trimmed first line, used by
// adapters to implement Version() and to detect a missing binary.
func toolVersion(ctx context.Context, bin string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s not available: %w", bin, err)
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line), nil
}
