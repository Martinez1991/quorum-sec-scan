package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"

	"github.com/quorum-sec/quorum/internal/model"
	"github.com/quorum-sec/quorum/internal/purl"
)

// BuildKey is a pure, deterministic function of normalized finding data. The
// key differs per Type — there is no single universal key (DESIGN §6).
func BuildKey(f model.Finding) string {
	switch f.Type {
	case model.TypeVuln:
		return "VULN|" + strings.ToUpper(f.VulnID) + "|" + purl.NameVersion(f.PURL)
	case model.TypeMisconfig:
		// Different engines disagree on both the file path (e.g. "main.tf" vs
		// "/main.tf" vs "../../work/x/main.tf") and the resource identity (the
		// Terraform address "aws_s3_bucket.data" vs the literal bucket name).
		// To make cross-engine consensus actually work we key on the file
		// basename + resource TYPE + canonical control. Trade-off: two distinct
		// resources of the same type with the same control in the same file may
		// over-merge — acceptable vs. never correlating at all (see KNOWN ISSUES).
		return "MISCONFIG|" + fileKey(f.Location.File) + "|" +
			resourceType(f.Resource) + "|" + controlKey(f)
	case model.TypeK8sPosture:
		return "K8S|" + objectRef(f.Resource) + "|" +
			strings.ToLower(f.Resource.Address) /*container*/ + "|" + controlKey(f)
	case model.TypeImgHardening:
		return "IMGH|" + controlKey(f)
	case model.TypeSecret:
		return "SECRET|" + normPath(f.Location.File) + "|" + lineKey(f) + "|" + strings.ToLower(f.RuleID)
	default:
		return "OTHER|" + f.Scanner + "|" + f.Title
	}
}

// Fingerprint is sha256(correlationKey), used as a portable dedup id in SARIF.
func Fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// controlKey prefers the resolved canonical control; when unmapped it falls
// back to the scanner-native rule id so an unmapped finding still never
// silently merges with a different one.
func controlKey(f model.Finding) string {
	if f.CanonicalControl != "" {
		return strings.ToUpper(f.CanonicalControl)
	}
	return "UNMAPPED:" + strings.ToLower(f.Scanner) + ":" + strings.ToUpper(f.RuleID)
}

func normPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return strings.ToLower(p)
}

// fileKey reduces a file path to its lowercased basename, the only portion
// that is stable across scanners (they report different roots/relativity).
func fileKey(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	return strings.ToLower(path.Base(p))
}

// resourceType derives a stable resource TYPE from a resource. It prefers the
// first dotted segment of the address that looks like a provider resource type
// (contains '_', e.g. "aws_s3_bucket" from "aws_s3_bucket.data" or
// "module.x.aws_s3_bucket.data"), falling back to the explicit Kind.
func resourceType(r model.Resource) string {
	for _, seg := range strings.Split(r.Address, ".") {
		if strings.Contains(seg, "_") {
			return strings.ToLower(seg)
		}
	}
	if r.Kind != "" {
		return strings.ToLower(r.Kind)
	}
	return strings.ToLower(strings.TrimSpace(r.Address))
}

func objectRef(r model.Resource) string {
	ns := r.Namespace
	if ns == "" {
		ns = "default"
	}
	return strings.ToLower(ns + "/" + r.Kind + "/" + r.Name)
}

func lineKey(f model.Finding) string {
	if f.Location.StartLine <= 0 {
		return "0"
	}
	// itoa without strconv import churn
	n := f.Location.StartLine
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
