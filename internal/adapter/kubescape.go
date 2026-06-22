package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
)

func init() { Register(&kubescape{}) }

type kubescape struct{}

func (kubescape) Name() string { return "kubescape" }

func (k kubescape) Version(ctx context.Context) (string, error) {
	return toolVersion(ctx, "kubescape", "version")
}

func (kubescape) Supports(target Target) bool {
	return target.Type == TargetK8s || target.Type == TargetRepo
}

func (kubescape) Capabilities() []Capability {
	return []Capability{{Type: model.TypeK8sPosture, Targets: []TargetType{TargetK8s}}}
}

func (k kubescape) Run(ctx context.Context, target Target) ([]model.Finding, error) {
	outDir, err := os.MkdirTemp("", "quorum-kubescape-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)
	outFile := filepath.Join(outDir, "ks.json")

	cmd := exec.CommandContext(ctx, "kubescape", "scan",
		target.Ref,
		"--format", "json",
		"--output", outFile,
		"--format-version", "v2",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	data, readErr := os.ReadFile(outFile)
	usable := readErr == nil && len(bytes.TrimSpace(data)) > 0

	// Like other scanners, kubescape may exit non-zero precisely because it found
	// failing controls while still writing a valid report — that is success. Only
	// treat the run as failed when it left us nothing usable to parse, and then
	// surface its stderr instead of a downstream "unexpected end of JSON input".
	if !usable {
		detail := strings.TrimSpace(stderr.String())
		switch {
		case runErr != nil:
			return nil, fmt.Errorf("kubescape: %w: %s", runErr, detail)
		case readErr != nil:
			return nil, fmt.Errorf("kubescape: report not produced: %w: %s", readErr, detail)
		default:
			return nil, fmt.Errorf("kubescape: empty report (no resources scanned?): %s", detail)
		}
	}

	ver, _ := k.Version(ctx)
	return k.parse(data, ver)
}

type ksReport struct {
	SummaryDetails struct {
		Controls map[string]struct {
			Name        string  `json:"name"`
			ScoreFactor float64 `json:"scoreFactor"`
		} `json:"controls"`
	} `json:"summaryDetails"`
	Results []struct {
		ResourceID string `json:"resourceID"`
		Controls   []struct {
			ControlID string `json:"controlID"`
			Name      string `json:"name"`
			Status    struct {
				Status string `json:"status"`
			} `json:"status"`
		} `json:"controls"`
	} `json:"results"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"resources"`
}

func (k kubescape) parse(data []byte, ver string) ([]model.Finding, error) {
	var rep ksReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	resByID := map[string]model.Resource{}
	for _, r := range rep.Resources {
		resByID[r.ResourceID] = model.Resource{
			Kind:      r.Object.Kind,
			Name:      r.Object.Metadata.Name,
			Namespace: r.Object.Metadata.Namespace,
		}
	}

	var out []model.Finding
	for _, res := range rep.Results {
		resource := resByID[res.ResourceID]
		for _, ctrl := range res.Controls {
			if ctrl.Status.Status != "failed" {
				continue
			}
			sf := rep.SummaryDetails.Controls[ctrl.ControlID].ScoreFactor
			out = append(out, model.Finding{
				Type:           model.TypeK8sPosture,
				Scanner:        "kubescape",
				ScannerVersion: ver,
				RuleID:         ctrl.ControlID,
				Severity:       ksSeverity(sf),
				Title:          firstNonEmpty(ctrl.Name, ctrl.ControlID),
				Resource:       resource,
			})
		}
	}
	return out, nil
}

// ksSeverity maps Kubescape's 0..10 scoreFactor to the canonical scale.
func ksSeverity(sf float64) model.Severity {
	switch {
	case sf >= 9:
		return model.SevCritical
	case sf >= 7:
		return model.SevHigh
	case sf >= 4:
		return model.SevMedium
	case sf > 0:
		return model.SevLow
	default:
		return model.SevMedium
	}
}
