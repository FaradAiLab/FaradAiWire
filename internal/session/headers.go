package session

import (
	"net/http"
	"strings"
)

// IngressHeadersBlocklist defines header keys that must NEVER be forwarded to upstream MCP servers.
// Lookup keys must be strictly lowercase.
var IngressHeadersBlocklist = map[string]bool{
	"authorization":           true,
	"x-api-key":               true,
	"cookie":                  true,
	"x-faradaiwire-signature": true,
	"x-faradaiwire-timestamp": true,
}

// IsBlockedIngressHeader determines whether an HTTP header should be stripped
// prior to dispatching outbound requests to remote upstream MCP servers.
func IsBlockedIngressHeader(headerKey string) bool {
	lower := strings.ToLower(strings.TrimSpace(headerKey))
	if IngressHeadersBlocklist[lower] {
		return true
	}
	// Strip all internal Farad Ai telemetry, provenance, and routing headers
	if strings.HasPrefix(lower, "x-faradaiwire-") {
		return true
	}
	// Strip standard hop-by-hop transport headers
	switch lower {
	case "connection",
		"upgrade",
		"accept-encoding",
		"content-length",
		"proxy-connection",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding":
		return true
	}
	return false
}

// IsBlockedUpstreamHeader determines whether a custom header configured on an upstream protocol
// should be prohibited (such as hop-by-hop transport or gateway-internal headers).
func IsBlockedUpstreamHeader(headerKey string) bool {
	lower := strings.ToLower(strings.TrimSpace(headerKey))
	if strings.HasPrefix(lower, "x-faradaiwire-") {
		return true
	}
	switch lower {
	case "connection",
		"upgrade",
		"accept-encoding",
		"content-length",
		"proxy-connection",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding":
		return true
	}
	return false
}

// SanitizeUpstreamHeaders filters inbound client headers by stripping credentials
// and hop-by-hop headers, while injecting the upstream target's configured auth token.
func SanitizeUpstreamHeaders(inboundHeaders http.Header, upstreamAuthToken string) http.Header {
	return SanitizeUpstreamHeadersWithCustom(inboundHeaders, upstreamAuthToken, nil)
}

// SanitizeUpstreamHeadersWithCustom filters inbound client headers by stripping credentials
// and hop-by-hop headers, while injecting the upstream target's configured auth token and custom headers.
func SanitizeUpstreamHeadersWithCustom(inboundHeaders http.Header, upstreamAuthToken string, customHeaders map[string]string) http.Header {
	out := make(http.Header)
	if inboundHeaders != nil {
		for k, vv := range inboundHeaders {
			if !IsBlockedIngressHeader(k) {
				for _, v := range vv {
					out.Add(k, v)
				}
			}
		}
	}

	upstreamAuthToken = strings.TrimSpace(upstreamAuthToken)
	if upstreamAuthToken != "" {
		if strings.HasPrefix(strings.ToLower(upstreamAuthToken), "bearer ") {
			out.Set("Authorization", upstreamAuthToken)
		} else {
			out.Set("Authorization", "Bearer "+upstreamAuthToken)
		}
	}

	for k, v := range customHeaders {
		k = strings.TrimSpace(k)
		if k != "" && !IsBlockedUpstreamHeader(k) {
			out.Set(k, v)
		}
	}

	return out
}
