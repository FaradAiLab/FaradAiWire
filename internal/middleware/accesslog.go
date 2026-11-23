package middleware

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
)

type accessLogResponseWriter struct {
	w           http.ResponseWriter
	statusCode  int
	wroteHeader bool
	bytes       int
}

func (rw *accessLogResponseWriter) Header() http.Header {
	return rw.w.Header()
}

func (rw *accessLogResponseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.statusCode = code
	rw.wroteHeader = true
	rw.w.WriteHeader(code)
}

func (rw *accessLogResponseWriter) Write(p []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.w.Write(p)
	rw.bytes += n
	return n, err
}

func (rw *accessLogResponseWriter) Flush() {
	if fl, ok := rw.w.(http.Flusher); ok {
		fl.Flush()
	}
}

func (rw *accessLogResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

func (rw *accessLogResponseWriter) Unwrap() http.ResponseWriter {
	return rw.w
}

// AccessLog returns an SSE/WebSocket-safe structured HTTP access log middleware for the named port role.
// It logs r.URL.Path only (never query strings, protecting Magic Link secrets) and updates OpenMetrics counters.
func AccessLog(port string) func(http.Handler) http.Handler {
	return AccessLogWithLogger(port, nil, metrics.Default())
}

// AccessLogWithLogger returns an HTTP access log middleware bound to an optional explicit logger and metrics registry.
// When logger is nil, slog.Default() is resolved per request.
func AccessLogWithLogger(port string, logger *slog.Logger, reg *metrics.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &accessLogResponseWriter{
				w:          w,
				statusCode: http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			if reg != nil {
				reg.IncHTTPResponse(port, rw.statusCode)
			}

			log := logger
			if log == nil {
				log = slog.Default()
			}
			if log == nil {
				return
			}

			level := slog.LevelInfo
			if r.URL != nil && r.URL.Path == "/health" && rw.statusCode < 400 {
				level = slog.LevelDebug
			} else if rw.statusCode >= 500 {
				level = slog.LevelError
			} else if rw.statusCode >= 400 {
				level = slog.LevelWarn
			}

			if !log.Enabled(r.Context(), level) {
				return
			}

			path := "/"
			if r.URL != nil && r.URL.Path != "" {
				path = r.URL.Path
			}
			log.Log(r.Context(), level, "HTTP request",
				slog.String("port", port),
				slog.String("method", r.Method),
				slog.String("path", path),
				slog.Int("status", rw.statusCode),
				slog.Int("bytes", rw.bytes),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
				slog.String("client_ip", ClientIP(r)),
			)
		})
	}
}
