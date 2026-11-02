package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_DefaultHeaders(t *testing.T) {
	cfg := DefaultSecurityConfig()
	middleware := SecurityHeaders(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	middleware(dummyHandler).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-XSS-Protection":       "0",
	}

	for k, v := range expectedHeaders {
		if got := res.Header.Get(k); got != v {
			t.Errorf("header %s: expected %q, got %q", k, v, got)
		}
	}
}

func TestSecurityHeaders_CORSAllowedOrigin(t *testing.T) {
	cfg := SecurityHeadersConfig{
		AllowedOrigins: []string{
			"https://app.faradai.security",
			"https://admin.faradai.security",
		},
	}
	middleware := SecurityHeaders(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sse", nil)
	req.Header.Set("Origin", "https://app.faradai.security")

	middleware(dummyHandler).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://app.faradai.security" {
		t.Errorf("expected Access-Control-Allow-Origin %q, got %q", "https://app.faradai.security", got)
	}
	if got := res.Header.Get("Vary"); got != "Origin" {
		t.Errorf("expected Vary: Origin, got %q", got)
	}
	if got := res.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials: true, got %q", got)
	}
}

func TestSecurityHeaders_CORSDisallowedOrigin(t *testing.T) {
	cfg := SecurityHeadersConfig{
		AllowedOrigins: []string{
			"https://app.faradai.security",
		},
	}
	middleware := SecurityHeaders(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/status", nil)
	req.Header.Set("Origin", "https://attacker-domain.evil")

	middleware(dummyHandler).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for unauthorized origin, got %q", got)
	}
}

func TestSecurityHeaders_PreflightOPTIONS(t *testing.T) {
	cfg := SecurityHeadersConfig{
		AllowedOrigins: []string{"https://app.faradai.security"},
	}
	middleware := SecurityHeaders(cfg)

	handlerCalled := false
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// 1. Allowed preflight
	recAllowed := httptest.NewRecorder()
	reqAllowed := httptest.NewRequest("OPTIONS", "/message", nil)
	reqAllowed.Header.Set("Origin", "https://app.faradai.security")

	middleware(dummyHandler).ServeHTTP(recAllowed, reqAllowed)
	resAllowed := recAllowed.Result()
	defer resAllowed.Body.Close()

	if resAllowed.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 No Content on allowed preflight, got %d", resAllowed.StatusCode)
	}
	if got := resAllowed.Header.Get("Access-Control-Allow-Origin"); got != "https://app.faradai.security" {
		t.Errorf("expected Access-Control-Allow-Origin on preflight, got %q", got)
	}
	if handlerCalled {
		t.Errorf("next handler should not be called on OPTIONS preflight")
	}

	// 2. Disallowed preflight
	recDisallowed := httptest.NewRecorder()
	reqDisallowed := httptest.NewRequest("OPTIONS", "/message", nil)
	reqDisallowed.Header.Set("Origin", "https://unauthorized-origin.com")

	middleware(dummyHandler).ServeHTTP(recDisallowed, reqDisallowed)
	resDisallowed := recDisallowed.Result()
	defer resDisallowed.Body.Close()

	if resDisallowed.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on disallowed preflight, got %d", resDisallowed.StatusCode)
	}
	if got := resDisallowed.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no Access-Control-Allow-Origin on disallowed preflight, got %q", got)
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	// Case 1: HSTS disabled, HTTP request
	cfgDisabled := SecurityHeadersConfig{EnableHSTS: false}
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/test", nil)
	SecurityHeaders(cfgDisabled)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec1, req1)
	if got := rec1.Result().Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("expected no HSTS header on plain HTTP without EnableHSTS, got %q", got)
	}

	// Case 2: EnableHSTS explicitly true
	cfgEnabled := SecurityHeadersConfig{EnableHSTS: true, HSTSMaxAge: 63072000}
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	SecurityHeaders(cfgEnabled)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec2, req2)
	if got := rec2.Result().Header.Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Errorf("expected HSTS header with max-age=63072000, got %q", got)
	}

	// Case 3: TLS connection present
	cfgDefault := DefaultSecurityConfig()
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.TLS = &tls.ConnectionState{}
	SecurityHeaders(cfgDefault)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec3, req3)
	if got := rec3.Result().Header.Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("expected standard HSTS on TLS request, got %q", got)
	}
}
