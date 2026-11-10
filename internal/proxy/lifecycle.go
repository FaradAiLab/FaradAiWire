package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SetDrainingMiddleware configures gateway ingress draining and in-flight tracking middleware.
func (s *SSEProxy) SetDrainingMiddleware(mw func(http.Handler) http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drainingMiddleware = mw
}

// SetHost configures the bind host address (e.g. "127.0.0.1" or "0.0.0.0").
func (s *SSEProxy) SetHost(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = strings.TrimSpace(host)
}

// Host returns the configured bind host address (defaults to 127.0.0.1).
func (s *SSEProxy) Host() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.host == "" {
		return "127.0.0.1"
	}
	return s.host
}

// Start spins up the HTTP server and blocks until ctx is canceled or a fatal error occurs.
func (s *SSEProxy) Start(ctx context.Context) error {
	handler := s.Handler()

	s.mu.Lock()
	host := s.host
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(s.port))
	s.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout remains 0 (unbounded) to sustain persistent, long-lived MCP event streams without premature timeouts (DEC-08).
	}
	server := s.server
	s.mu.Unlock()

	slog.Info("Farad Ai SSE Proxy listening", slog.String("host", host), slog.Int("port", s.port))

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("SSE Proxy server error", slog.String("error", err.Error()))
			errCh <- err
		} else {
			errCh <- nil
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	}
}

func (s *SSEProxy) lifecycleCtx() context.Context {
	s.mu.RLock()
	closed := s.closed
	ctx := s.baseCtx
	s.mu.RUnlock()
	if closed {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		return canceledCtx
	}
	if ctx != nil {
		return ctx
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		return canceledCtx
	}
	if s.baseCtx == nil {
		s.baseCtx, s.baseCancel = context.WithCancel(context.Background())
	}
	return s.baseCtx
}

// Shutdown initiates graceful termination of the SSE proxy server listener,
// canceling detached message bridges only after active HTTP requests drain.
func (s *SSEProxy) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		server := s.server
		cancel := s.baseCancel
		s.mu.Unlock()

		if server != nil {
			slog.Info("Shutting down SSE proxy server...")
			shutdownErr = server.Shutdown(ctx)
		}
		if cancel != nil {
			cancel()
		}
	})
	return shutdownErr
}

// Server returns the underlying active http.Server instance if started (useful for timeout assertions).
func (s *SSEProxy) Server() *http.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.server
}

// BroadcastShutdownEvent sends a shutdown event frame to all active SSE client streams without terminating upstreams.
func (s *SSEProxy) BroadcastShutdownEvent() {
	if s == nil {
		return
	}
	mgr := s.SessionManager()
	if mgr == nil {
		return
	}
	mgr.BroadcastShutdownEvent()
}

// DrainActiveStreams broadcasts a shutdown event to all connected SSE clients and actively evicts bridges.
func (s *SSEProxy) DrainActiveStreams() {
	if s == nil {
		return
	}
	mgr := s.SessionManager()
	if mgr == nil {
		return
	}
	mgr.DrainAllBridges()
}
