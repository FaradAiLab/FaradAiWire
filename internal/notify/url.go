package notify

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// BuildAdminBaseURL normalizes unspecified bind hosts ("", "0.0.0.0", "::", "[::]")
// to loopback addresses and formats a scheme+host+port base URL suitable for browser
// navigation without violating AdminServer's strict loopback Origin/CSRF policy.
func BuildAdminBaseURL(host string, port int, tlsEnabled bool) string {
	if port <= 0 || port > 65535 {
		return ""
	}

	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "", "0.0.0.0":
		h = "127.0.0.1"
	case "::":
		h = "::1"
	}

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}

	return scheme + "://" + net.JoinHostPort(h, strconv.Itoa(port))
}

// BuildAdminDashboardURL constructs a validated Admin Console dashboard URL targeting
// the specified hash fragment (e.g. "guards" or "audit").
func BuildAdminDashboardURL(host string, port int, tlsEnabled bool, fragment string) string {
	base := BuildAdminBaseURL(host, port, tlsEnabled)
	if base == "" {
		return ""
	}
	return BuildDashboardURLFromBase(base, fragment)
}

// BuildDashboardURLFromBase appends /admin/dashboard and a sanitized hash fragment
// to an already-normalized admin base URL. Returns "" if baseURL is invalid.
func BuildDashboardURLFromBase(baseURL, fragment string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !ValidateHTTPURL(trimmed) {
		return ""
	}

	target := trimmed + "/admin/dashboard"
	if cleanFrag := sanitizeFragment(fragment); cleanFrag != "" {
		target += "#" + cleanFrag
	}
	return target
}

// ValidateHTTPURL verifies that raw is a well-formed http:// or https:// URL with
// a non-empty host and no ASCII control characters.
func ValidateHTTPURL(raw string) bool {
	if raw == "" {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.User != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func sanitizeFragment(fragment string) string {
	cleaned := strings.TrimPrefix(strings.TrimSpace(fragment), "#")
	if cleaned == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(cleaned))
	for i := 0; i < len(cleaned); i++ {
		ch := cleaned[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if isAlphaNum || ch == '_' || ch == '-' {
			b.WriteByte(ch)
		}
	}
	return b.String()
}
