// Package report serializes a scan result into SARIF (primary), JSON, or XML.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/quorum-sec/quorum/internal/orchestrator"
)

// Format is an output format selector.
type Format string

const (
	FormatSARIF Format = "sarif"
	FormatJSON  Format = "json"
	FormatXML   Format = "xml"
)

// ParseFormat validates a --format flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatSARIF:
		return FormatSARIF, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatXML:
		return FormatXML, nil
	default:
		return "", fmt.Errorf("unknown format %q (want sarif|json|xml)", s)
	}
}

// Write renders res in the given format to w.
func Write(w io.Writer, res *orchestrator.Result, format Format) error {
	switch format {
	case FormatSARIF:
		return writeSARIF(w, res)
	case FormatJSON:
		return writeJSON(w, res)
	case FormatXML:
		return writeXML(w, res)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
