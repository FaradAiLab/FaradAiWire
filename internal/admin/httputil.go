package admin

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

const (
	// maxAdminBodyBytes bounds standard administrative JSON payloads (configs, agents, protocols, policies).
	maxAdminBodyBytes int64 = 1 << 20
	// maxSmallAdminBodyBytes bounds lightweight administrative control payloads (guard settings, HITL, schema pin).
	maxSmallAdminBodyBytes int64 = 64 << 10
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Warn("Failed to encode admin JSON response", slog.String("error", err.Error()))
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

func writeMethodNotAllowed(w http.ResponseWriter, allow, message string) {
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
	if message == "" {
		message = "Method not allowed"
	}
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", message)
}

// decodeJSON enforces an explicit http.MaxBytesReader cap before decoding JSON into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	if maxBytes <= 0 {
		maxBytes = maxAdminBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

var exactMuxMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

// registerExactMethods binds handler to path strictly for the allowed HTTP methods and explicitly
// binds a JSON 405 Method Not Allowed handler to all other standard methods so literal paths
// cleanly shadow wildcard siblings across every HTTP method under Go 1.22+ ServeMux.
func registerExactMethods(mux *http.ServeMux, path string, handler http.HandlerFunc, allowed ...string) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, m := range allowed {
		allowedSet[m] = true
		mux.HandleFunc(m+" "+path, handler)
	}
	allowHeader := strings.Join(allowed, ", ")
	for _, m := range exactMuxMethods {
		// Go 1.22+ ServeMux maps HEAD to GET implicitly and rejects duplicate HEAD+GET registration.
		if allowedSet[m] || (m == http.MethodHead && allowedSet[http.MethodGet]) {
			continue
		}
		mux.HandleFunc(m+" "+path, func(w http.ResponseWriter, _ *http.Request) {
			writeMethodNotAllowed(w, allowHeader, "Method not allowed")
		})
	}
}

// withJSONMethodNotAllowed adapts Go 1.22+ ServeMux plain-text 405 Method Not Allowed responses
// into standardized JSON {"error":"METHOD_NOT_ALLOWED",...} payloads while preserving Allow headers.
func withJSONMethodNotAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			next.ServeHTTP(w, r)
			return
		}
		rec := &methodNotAllowedJSONWriter{ResponseWriter: w}
		next.ServeHTTP(rec, r)
	})
}

type methodNotAllowedJSONWriter struct {
	http.ResponseWriter
	wroteHeader bool
	intercepted bool
}

func (w *methodNotAllowedJSONWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if code == http.StatusMethodNotAllowed && !strings.Contains(strings.ToLower(w.Header().Get("Content-Type")), "application/json") {
		w.intercepted = true
		w.Header().Del("Content-Length")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.ResponseWriter.Write([]byte(`{"error":"METHOD_NOT_ALLOWED","message":"Method not allowed"}` + "\n"))
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *methodNotAllowedJSONWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercepted {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *methodNotAllowedJSONWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *methodNotAllowedJSONWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	return h.Hijack()
}

func (w *methodNotAllowedJSONWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
