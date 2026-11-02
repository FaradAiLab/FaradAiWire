package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebHandler_ServesSPA(t *testing.T) {
	h := Handler()

	// 1. Root path "/"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"root\"></div>") {
		t.Errorf("expected root div in body, got: %s", rec.Body.String())
	}

	// 2. "/admin/dashboard"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/dashboard", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin/dashboard, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "FaradAiWire") {
		t.Errorf("expected FaradAiWire in title/body, got: %s", rec.Body.String())
	}

	// 3. Client route fallback "/overview"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/overview", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /overview, got %d", rec.Code)
	}

	// 4. API 404 should not return HTML
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/unknown-endpoint", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown admin endpoint, got %d", rec.Code)
	}
}
