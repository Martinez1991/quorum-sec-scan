// Package purl provides minimal Package-URL helpers. Adapters build PURLs and
// the correlator extracts the name@version portion for the VULN key, so the
// same package "log4j-core@2.14.1" correlates regardless of which scanner's
// ecosystem prefix or qualifiers came along for the ride.
package purl

import (
	"net/url"
	"strings"
)

// Build assembles a PURL from its parts: pkg:<typ>/<namespace>/<name>@<version>.
// namespace may be empty. version may be empty.
func Build(typ, namespace, name, version string) string {
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(strings.ToLower(typ))
	b.WriteByte('/')
	if namespace != "" {
		b.WriteString(escape(namespace))
		b.WriteByte('/')
	}
	b.WriteString(escape(name))
	if version != "" {
		b.WriteByte('@')
		b.WriteString(escape(version))
	}
	return b.String()
}

// NameVersion extracts the canonical "<type>/<ns>/<name>@<version>" identity
// from a PURL, dropping the "pkg:" scheme and any ?qualifiers / #subpath so
// that only ecosystem + package identity remain. Returns the lowercased,
// trimmed remainder; for an empty/invalid purl returns "".
func NameVersion(p string) string {
	if p == "" {
		return ""
	}
	s := strings.TrimSpace(p)
	s = strings.TrimPrefix(s, "pkg:")
	// strip qualifiers and subpath
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// Name returns just the package name portion (no type/namespace/version),
// best-effort, for display.
func Name(p string) string {
	nv := NameVersion(p)
	if nv == "" {
		return ""
	}
	if i := strings.LastIndexByte(nv, '@'); i >= 0 {
		nv = nv[:i]
	}
	if i := strings.LastIndexByte(nv, '/'); i >= 0 {
		nv = nv[i+1:]
	}
	return nv
}

func escape(s string) string {
	// PURL uses percent-encoding for reserved chars; url.PathEscape is close
	// enough for the identity-stability purpose here.
	return strings.ReplaceAll(url.PathEscape(s), "%2F", "/")
}
