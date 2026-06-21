package report

import (
	"encoding/xml"
	"io"

	"github.com/quorum-sec/quorum/internal/orchestrator"
)

// XML mirrors the JSON structure, serialized for legacy/JUnit-like pipelines.

type xmlReport struct {
	XMLName  xml.Name     `xml:"quorumReport"`
	Tool     string       `xml:"tool,attr"`
	Version  string       `xml:"version,attr"`
	Target   xmlTarget    `xml:"target"`
	Scanners []xmlScanner `xml:"scanners>scanner"`
	Findings []xmlFinding `xml:"findings>finding"`
}

type xmlTarget struct {
	Type string `xml:"type,attr"`
	Ref  string `xml:",chardata"`
}

type xmlScanner struct {
	Name     string `xml:"name,attr"`
	Status   string `xml:"status,attr"`
	Version  string `xml:"version,attr,omitempty"`
	Findings int    `xml:"findings,attr"`
	Error    string `xml:"error,attr,omitempty"`
}

type xmlFinding struct {
	Type           string   `xml:"type,attr"`
	Severity       string   `xml:"severity,attr"`
	DetectionCount int      `xml:"detectionCount,attr"`
	Confidence     float64  `xml:"confidence,attr"`
	Unmapped       bool     `xml:"unmapped,attr,omitempty"`
	Fingerprint    string   `xml:"fingerprint,attr"`
	CorrelationKey string   `xml:"correlationKey"`
	Title          string   `xml:"title"`
	DetectedBy     []string `xml:"detectedBy>scanner"`
	Locations      []xmlLoc `xml:"locations>location,omitempty"`
}

type xmlLoc struct {
	File      string `xml:"file,attr,omitempty"`
	StartLine int    `xml:"startLine,attr,omitempty"`
	EndLine   int    `xml:"endLine,attr,omitempty"`
}

func writeXML(w io.Writer, res *orchestrator.Result) error {
	rep := xmlReport{
		Tool:    "quorum",
		Version: Version,
		Target:  xmlTarget{Type: string(res.Target.Type), Ref: res.Target.Ref},
	}
	for _, r := range res.Runs {
		rep.Scanners = append(rep.Scanners, xmlScanner{
			Name: r.Name, Status: r.Status, Version: r.Version,
			Findings: r.Findings, Error: r.Error,
		})
	}
	for _, m := range res.Merged {
		f := xmlFinding{
			Type:           string(m.Type),
			Severity:       string(m.Severity),
			DetectionCount: m.DetectionCount,
			Confidence:     round2(m.Confidence),
			Unmapped:       m.Unmapped,
			Fingerprint:    m.Fingerprint,
			CorrelationKey: m.CorrelationKey,
			Title:          m.Title,
			DetectedBy:     m.DetectedBy,
		}
		seen := map[string]struct{}{}
		for _, mem := range m.Members {
			if mem.Location.File == "" {
				continue
			}
			if _, ok := seen[mem.Location.File]; ok {
				continue
			}
			seen[mem.Location.File] = struct{}{}
			f.Locations = append(f.Locations, xmlLoc{
				File: mem.Location.File, StartLine: mem.Location.StartLine, EndLine: mem.Location.EndLine,
			})
		}
		rep.Findings = append(rep.Findings, f)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
