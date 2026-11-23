package middleware

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
)

type spyFlusherHijackerRecorder struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
}

func (s *spyFlusherHijackerRecorder) Flush() {
	s.flushed = true
	s.ResponseRecorder.Flush()
}

func (s *spyFlusherHijackerRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.hijacked = true
	return nil, nil, nil
}

func TestAccessLog_PreservesFlusherHijackerAndUnwrap(t *testing.T) {
	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	mw := AccessLogWithLogger("admin", log, metrics.NewRegistry())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected wrapped ResponseWriter to implement http.Flusher")
		}
		w.WriteHeader(http.StatusCreated)
		fl.Flush()

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("expected wrapped ResponseWriter to implement http.Hijacker")
		}
		_, _, _ = hj.Hijack()

		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			t.Fatalf("expected ResponseController.Flush (Unwrap) to succeed, got %v", err)
		}
	}))

	rec := &spyFlusherHijackerRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/events", nil)
	handler.ServeHTTP(rec, req)

	if !rec.flushed {
		t.Error("expected underlying Flush() to be invoked")
	}
	if !rec.hijacked {
		t.Error("expected underlying Hijack() to be invoked")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec.Code)
	}
}

func TestAccessLog_ScrubsQuerySecretsSuppressesHealthAndRecordsMetrics(t *testing.T) {
	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reg := metrics.NewRegistry()

	mw := AccessLogWithLogger("admin", log, reg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.URL.Query().Get("fail") == "1" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Magic Link token query param MUST never leak into logs
	reqSecret := httptest.NewRequest(http.MethodGet, "/admin/dashboard?token=super_secret_magic_token_999&foo=bar", nil)
	handler.ServeHTTP(httptest.NewRecorder(), reqSecret)

	logged := logBuf.String()
	if !strings.Contains(logged, `"/admin/dashboard"`) {
		t.Fatalf("expected sanitized path /admin/dashboard in log, got %s", logged)
	}
	if strings.Contains(logged, "super_secret_magic_token_999") || strings.Contains(logged, "token=") {
		t.Fatalf("secret query parameter leaked into access log: %s", logged)
	}

	// 2. Healthy /health probes suppressed at Info level
	logBuf.Reset()
	reqHealthOK := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(httptest.NewRecorder(), reqHealthOK)
	if logBuf.Len() != 0 {
		t.Errorf("expected 200 /health to be suppressed at Info level, got %s", logBuf.String())
	}

	// 3. Failing /health (>=400) IS logged at Info/Warn level
	reqHealthFail := httptest.NewRequest(http.MethodGet, "/health?fail=1", nil)
	handler.ServeHTTP(httptest.NewRecorder(), reqHealthFail)
	if !strings.Contains(logBuf.String(), `"/health"`) {
		t.Errorf("expected 503 /health to be logged, got %s", logBuf.String())
	}

	// 4. OpenMetrics HTTP response counter recorded for 2xx and 5xx
	prom := reg.RenderPrometheus()
	if !strings.Contains(prom, `faradaiwire_http_responses_total{code_class="2xx",port="admin"} 2`) {
		t.Errorf("expected 2xx count=2 in Prometheus output, got:\n%s", prom)
	}
	if !strings.Contains(prom, `faradaiwire_http_responses_total{code_class="5xx",port="admin"} 1`) {
		t.Errorf("expected 5xx count=1 in Prometheus output, got:\n%s", prom)
	}
}
