package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

// SecurityHeadersConfig holds configuration options for security headers and CORS enforcement.
type SecurityHeadersConfig struct {
	AllowedOrigins        []string          // Allowed origins for CORS; wildcard "*" allows all origins.
	ContentSecurityPolicy string            // Custom CSP directive; defaults to strict standard CSP.
	ReferrerPolicy        string            // Custom Referrer-Policy; defaults to strict-origin-when-cross-origin.
	EnableHSTS            bool              // If true or if request is TLS, sets Strict-Transport-Security.
	HSTSMaxAge            int               // Max-age for HSTS in seconds (default 31536000).
	CustomHeaders         map[string]string // Additional static security headers.
}

// DefaultSecurityConfig returns standard safe defaults.
func DefaultSecurityConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		HSTSMaxAge:            31536000,
	}
}

// SecurityHeaders returns an HTTP middleware that injects defensive security headers
// and enforces strict, configurable CORS origin restrictions.
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	csp := strings.TrimSpace(cfg.ContentSecurityPolicy)
	if csp == "" {
		csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
	}

	refPolicy := strings.TrimSpace(cfg.ReferrerPolicy)
	if refPolicy == "" {
		refPolicy = "strict-origin-when-cross-origin"
	}

	hstsMaxAge := cfg.HSTSMaxAge
	if hstsMaxAge <= 0 {
		hstsMaxAge = 31536000
	}

	// Pre-process allowed origins for efficient lookup
	allowAllOrigins := false
	allowedMap := make(map[string]bool)
	for _, origin := range cfg.AllowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "*" {
			allowAllOrigins = true
		} else if trimmed != "" {
			allowedMap[strings.ToLower(trimmed)] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// 1. Set Defensive HTTP Security Headers
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", csp)
			h.Set("Referrer-Policy", refPolicy)
			h.Set("X-XSS-Protection", "0")

			// Apply HSTS if enabled or if connection is TLS/HTTPS
			if cfg.EnableHSTS || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				h.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", hstsMaxAge))
			}

			// Apply any custom headers
			for k, v := range cfg.CustomHeaders {
				if k != "" && v != "" {
					h.Set(k, v)
				}
			}

			// 2. Process CORS Allowlist
			origin := r.Header.Get("Origin")
			originAllowed := false

			if origin != "" {
				originLower := strings.ToLower(strings.TrimSpace(origin))
				if allowAllOrigins {
					originAllowed = true
					h.Set("Access-Control-Allow-Origin", "*")
					h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
					h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Trace-ID, X-User-Role, X-User-ID, X-FaradAiWire-Signature, Accept, Origin")
				} else if allowedMap[originLower] {
					originAllowed = true
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Vary", "Origin")
					h.Set("Access-Control-Allow-Credentials", "true")
					h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
					h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Trace-ID, X-User-Role, X-User-ID, X-FaradAiWire-Signature, Accept, Origin")
				}
			}

			// 3. Handle Preflight OPTIONS requests
			if r.Method == http.MethodOptions {
				if origin != "" && !originAllowed && !allowAllOrigins {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if next != nil {
				next.ServeHTTP(w, r)
			}
		})
	}
}
