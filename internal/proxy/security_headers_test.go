package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestSSEProxy_SecurityHeadersAndCORS(t *testing.T) {
	userCtxCfg := config.UserContextConfig{
		FallbackRole: "Developer",
		FallbackUser: "dev-user",
	}
	secCfg := config.SecurityConfig{
		CORSAllowedOrigins: []string{
			"https://app.faradai.security",
			"https://console.faradai.security",
		},
	}

	pipeline := filter.NewPipeline(nil)
	proxy := NewSSEProxy(8080, "http://localhost:8081/sse", pipeline, nil, nil, userCtxCfg, secCfg)
	handler := proxy.Handler()

	t.Run("Security headers on /sse and /message", func(t *testing.T) {
		for _, path := range []string{"/sse", "/message"} {
			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("%s: expected X-Content-Type-Options: nosniff, got %q", path, got)
			}
			if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("%s: expected X-Frame-Options: DENY, got %q", path, got)
			}
			if got := res.Header.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
				t.Errorf("%s: expected Referrer-Policy: strict-origin-when-cross-origin, got %q", path, got)
			}
			if got := res.Header.Get("Content-Security-Policy"); got == "" {
				t.Errorf("%s: expected non-empty Content-Security-Policy header", path)
			}
		}
	})

	t.Run("CORS Allowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/message", nil)
		req.Header.Set("Origin", "https://app.faradai.security")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://app.faradai.security" {
			t.Errorf("expected Access-Control-Allow-Origin %q, got %q", "https://app.faradai.security", got)
		}
		if got := res.Header.Get("Vary"); got != "Origin" {
			t.Errorf("expected Vary: Origin, got %q", got)
		}
	})

	t.Run("CORS Disallowed Origin - No wildcard or reflection", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/message", nil)
		req.Header.Set("Origin", "https://malicious-site.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("expected no Access-Control-Allow-Origin for unauthorized origin, got %q", got)
		}
	})

	t.Run("Preflight OPTIONS Handling", func(t *testing.T) {
		// Allowed preflight
		reqOptAllowed := httptest.NewRequest("OPTIONS", "/message", nil)
		reqOptAllowed.Header.Set("Origin", "https://console.faradai.security")
		recOptAllowed := httptest.NewRecorder()
		handler.ServeHTTP(recOptAllowed, reqOptAllowed)

		if recOptAllowed.Result().StatusCode != http.StatusNoContent {
			t.Errorf("expected 204 No Content, got %d", recOptAllowed.Result().StatusCode)
		}
		if got := recOptAllowed.Result().Header.Get("Access-Control-Allow-Origin"); got != "https://console.faradai.security" {
			t.Errorf("expected allowed origin on preflight, got %q", got)
		}

		// Disallowed preflight
		reqOptDisallowed := httptest.NewRequest("OPTIONS", "/message", nil)
		reqOptDisallowed.Header.Set("Origin", "https://evil.org")
		recOptDisallowed := httptest.NewRecorder()
		handler.ServeHTTP(recOptDisallowed, reqOptDisallowed)

		if recOptDisallowed.Result().StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", recOptDisallowed.Result().StatusCode)
		}
	})
}
