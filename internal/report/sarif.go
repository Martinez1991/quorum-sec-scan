package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/orchestrator"
)

// Version is stamped into the SARIF tool driver and the fingerprint namespace.
var Version = "0.1.0"

const fingerprintKey = "quorum/v1"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
	Props   map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}

func writeSARIF(w io.Writer, res *orchestrator.Result) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(res.Merged))

	for _, m := range res.Merged {
		ruleID := sarifRuleID(m)
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             string(m.Type),
				ShortDescription: sarifText{Text: m.Title},
				Properties: map[string]any{
					"type": string(m.Type),
				},
			}
		}
		results = append(results, sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(m.Severity),
			Message:             sarifText{Text: m.Title},
			Locations:           sarifLocations(m),
			PartialFingerprints: map[string]string{fingerprintKey: m.Fingerprint},
			Properties: map[string]any{
				"detectedBy":     m.DetectedBy,
				"detectionCount": m.DetectionCount,
				"confidence":     round2(m.Confidence),
				"severity":       string(m.Severity),
				"correlationKey": m.CorrelationKey,
				"unmapped":       m.Unmapped,
			},
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "quorum",
				InformationURI: "https://github.com/quorum-sec/quorum",
				Version:        Version,
				Rules:          ruleList,
			}},
			Results: results,
			Props: map[string]any{
				"target":   res.Target.Ref,
				"scanners": scannerSummary(res),
			},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func sarifRuleID(m model.MergedFinding) string {
	switch m.Type {
	case model.TypeVuln:
		if len(m.Members) > 0 && m.Members[0].VulnID != "" {
			return m.Members[0].VulnID
		}
	default:
		if len(m.Members) > 0 && m.Members[0].CanonicalControl != "" {
			return m.Members[0].CanonicalControl
		}
		if len(m.Members) > 0 && m.Members[0].RuleID != "" {
			return m.Members[0].RuleID
		}
	}
	return m.CorrelationKey
}

func sarifLocations(m model.MergedFinding) []sarifLocation {
	seen := map[string]struct{}{}
	var locs []sarifLocation
	for _, mem := range m.Members {
		if mem.Location.File == "" {
			continue
		}
		key := mem.Location.File
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		var region *sarifRegion
		if mem.Location.StartLine > 0 {
			region = &sarifRegion{StartLine: mem.Location.StartLine, EndLine: mem.Location.EndLine}
		}
		locs = append(locs, sarifLocation{PhysicalLocation: sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: mem.Location.File},
			Region:           region,
		}})
	}
	return locs
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func scannerSummary(res *orchestrator.Result) []map[string]any {
	out := make([]map[string]any, 0, len(res.Runs))
	for _, r := range res.Runs {
		out = append(out, map[string]any{
			"name":    r.Name,
			"status":  r.Status,
			"version": r.Version,
		})
	}
	return out
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
