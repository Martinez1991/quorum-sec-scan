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
		return "MISCONFIG|" + normPath(f.Location.File) + "|" +
			normResource(f.Resource.Address) + "|" + controlKey(f)
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

func normResource(addr string) string {
	return strings.ToLower(strings.TrimSpace(addr))
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
