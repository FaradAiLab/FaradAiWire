package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPUtil_WriteHelpersAndDecodeJSON(t *testing.T) {
	t.Parallel()

	t.Run("writeError formats JSON error payload", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		writeError(rec, http.StatusBadRequest, "BAD_REQUEST", "missing field")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("expected application/json Content-Type, got %q", ct)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if body["error"] != "BAD_REQUEST" || body["message"] != "missing field" {
			t.Fatalf("unexpected error body: %+v", body)
		}
	})

	t.Run("decodeJSON rejects oversized body via MaxBytesReader", func(t *testing.T) {
		t.Parallel()
		oversized := `{"name":"` + strings.Repeat("a", int(maxSmallAdminBodyBytes)+256) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(oversized))
		rec := httptest.NewRecorder()
		var dst struct {
			Name string `json:"name"`
		}
		err := decodeJSON(rec, req, maxSmallAdminBodyBytes, &dst)
		if err == nil {
			t.Fatal("expected decodeJSON to fail on oversized payload")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected MaxBytesReader error, got: %v", err)
		}
	})

	t.Run("withJSONMethodNotAllowed converts ServeMux plain-text 405 into JSON and preserves nosniff", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		mux.HandleFunc("GET /admin/ping", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		})
		h := withJSONMethodNotAllowed(mux)

		rec := httptest.NewRecorder()
		rec.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/ping", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
			t.Fatalf("expected Allow header preserved, got %q", allow)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("expected JSON body on 405, got %q (%v)", rec.Body.String(), err)
		}
		if body["error"] != "METHOD_NOT_ALLOWED" {
			t.Fatalf("error = %q, want METHOD_NOT_ALLOWED", body["error"])
		}
	})
}

func TestAdminServer_MaxBytesEnforcedOnPolicyAndAPIKeys(t *testing.T) {
	t.Parallel()

	oversized := `{"name":"` + strings.Repeat("x", int(maxAdminBodyBytes)+1024) + `"}`
	srv, _ := setupTestAdminServerWithKeyStore()
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewBufferString(oversized))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized /admin/api-keys payload, got %d: %s", rec.Code, rec.Body.String())
	}

	policySrv, _, _, _ := setupTestAdminServerWithPolicy(t)
	policyHandler := policySrv.Handler()
	for _, path := range []string{"/admin/dlp/rules", "/admin/policy-packs"} {
		pReq := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(oversized))
		pReq.Header.Set("Content-Type", "application/json")
		pRec := httptest.NewRecorder()
		policyHandler.ServeHTTP(pRec, pReq)
		if pRec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for oversized %s payload, got %d: %s", path, pRec.Code, pRec.Body.String())
		}
	}
}

func TestAdminServer_RouteSpecificity(t *testing.T) {
	t.Parallel()

	srv := NewAdminServer(AdminDependencies{})
	handler := srv.Handler()

	cases := []struct {
		method string
		path   string
		allow  string
	}{
		{method: http.MethodPost, path: "/admin/protocols/presets", allow: http.MethodGet},
		{method: http.MethodPost, path: "/admin/agents/archives", allow: http.MethodGet},
		{method: http.MethodGet, path: "/admin/guards/models/deactivate", allow: http.MethodPost},
		{method: http.MethodHead, path: "/admin/guards/models/deactivate", allow: http.MethodPost},
		{method: http.MethodGet, path: "/admin/policy-packs/recommend", allow: http.MethodPost},
		{method: http.MethodGet, path: "/admin/schemas/clear", allow: http.MethodPost},
		{method: http.MethodPost, path: "/admin/audit-logs/events", allow: http.MethodGet},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405 Method Not Allowed (body: %s)", rec.Code, rec.Body.String())
			}
			if gotAllow := rec.Header().Get("Allow"); !strings.Contains(gotAllow, tc.allow) {
				t.Fatalf("Allow = %q, want substring %q", gotAllow, tc.allow)
			}
			if gotNoSniff := rec.Header().Get("X-Content-Type-Options"); gotNoSniff != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q, want nosniff", gotNoSniff)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("expected JSON 405 body, got %q (%v)", rec.Body.String(), err)
			}
			if body["error"] != "METHOD_NOT_ALLOWED" {
				t.Fatalf("error = %q, want METHOD_NOT_ALLOWED", body["error"])
			}
		})
	}
}

func TestAdminServer_GuardProbeRejectsMalformedJSON_AndArchiveSyncReturnJSONErrors(t *testing.T) {
	t.Parallel()

	srv := NewAdminServer(AdminDependencies{})
	handler := srv.Handler()

	// Malformed JSON body on POST /admin/guards/probe must fail closed with JSON 400.
	badReq := httptest.NewRequest(http.MethodPost, "/admin/guards/probe", strings.NewReader("{bad-json"))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("POST malformed JSON /admin/guards/probe status = %d, want 400: %s", badRec.Code, badRec.Body.String())
	}
	var badBody map[string]string
	if err := json.Unmarshal(badRec.Body.Bytes(), &badBody); err != nil || badBody["error"] != "BAD_REQUEST" {
		t.Fatalf("expected JSON BAD_REQUEST, got %q (%v)", badRec.Body.String(), err)
	}

	// Empty POST /admin/guards/probe still succeeds.
	emptyReq := httptest.NewRequest(http.MethodPost, "/admin/guards/probe", http.NoBody)
	emptyRec := httptest.NewRecorder()
	handler.ServeHTTP(emptyRec, emptyReq)
	if emptyRec.Code != http.StatusOK {
		t.Fatalf("POST empty /admin/guards/probe status = %d, want 200: %s", emptyRec.Code, emptyRec.Body.String())
	}

	// Archive and sync-tools validation errors return structured JSON.
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/admin/agents/archives", body: ""},
		{method: http.MethodPost, path: "/admin/agents/rollback", body: "{}"},
		{method: http.MethodPost, path: "/admin/agents/sync-tools", body: "{}"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s status = %d, want 400: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		var errBody map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["error"] != "BAD_REQUEST" {
			t.Fatalf("%s %s expected JSON BAD_REQUEST, got %q (%v)", tc.method, tc.path, rec.Body.String(), err)
		}
	}
}
