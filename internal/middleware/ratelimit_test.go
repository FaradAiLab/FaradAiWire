package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "Standard RemoteAddr with port",
			remoteAddr: "192.168.1.50:54321",
			expectedIP: "192.168.1.50",
		},
		{
			name: "X-Forwarded-For single IP ignored in favor of socket IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For multiple proxies ignored in favor of socket IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195, 70.41.3.18, 150.172.238.178",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Real-IP header ignored in favor of socket IP",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.42",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "IPv6 loopback with port stripped of brackets",
			remoteAddr: "[::1]:54321",
			expectedIP: "::1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "127.0.0.1",
			expectedIP: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			ip := ClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestHTTPRateLimit_SpoofedXFF_CannotBypass(t *testing.T) {
	// Rate limit: 1 req/sec, burst of 3
	mw := HTTPRateLimit(1.0, 3)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	socketAddr := "192.168.1.100:54321"

	// Send 3 requests within burst capacity, each presenting a different spoofed X-Forwarded-For header
	spoofedIPs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for i, spoofIP := range spoofedIPs {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = socketAddr
		req.Header.Set("X-Forwarded-For", spoofIP)
		req.Header.Set("X-Real-IP", spoofIP)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d within burst should succeed, got HTTP %d", i+1, rec.Code)
		}
	}

	// 4th request from same socket address with yet another spoofed IP must be rejected with HTTP 429
	req4 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req4.RemoteAddr = socketAddr
	req4.Header.Set("X-Forwarded-For", "4.4.4.4")
	req4.Header.Set("X-Real-IP", "4.4.4.4")
	rec4 := httptest.NewRecorder()

	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 Too Many Requests on 4th request despite spoofed XFF, got HTTP %d", rec4.Code)
	}
}

func TestTokenBucketLimiter_BurstAndRefill(t *testing.T) {
	// 5 tokens/sec, burst of 3
	limiter := NewTokenBucketLimiter(5.0, 3)
	ip := "192.0.2.1"

	// 3 requests should be permitted (burst capacity)
	if !limiter.Allow(ip) {
		t.Fatal("Request 1 should be allowed")
	}
	if !limiter.Allow(ip) {
		t.Fatal("Request 2 should be allowed")
	}
	if !limiter.Allow(ip) {
		t.Fatal("Request 3 should be allowed")
	}

	// 4th request must be rejected immediately
	if limiter.Allow(ip) {
		t.Fatal("Request 4 should be rejected (burst exhausted)")
	}

	// Wait 250ms -> should refill ~1.25 tokens -> at least 1 request allowed
	time.Sleep(250 * time.Millisecond)
	if !limiter.Allow(ip) {
		t.Fatal("Request after refill should be allowed")
	}
}

func TestTokenBucketLimiter_HTTPMiddleware(t *testing.T) {
	// 1 token/sec, burst of 2
	mw := HTTPRateLimit(1.0, 2)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	ip := "192.0.2.99"

	// Request 1: OK
	req1 := httptest.NewRequest("GET", "/sse", nil)
	req1.RemoteAddr = ip + ":1234"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec1.Code)
	}

	// Request 2: OK
	req2 := httptest.NewRequest("GET", "/sse", nil)
	req2.RemoteAddr = ip + ":1234"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	// Request 3: 429 Too Many Requests
	req3 := httptest.NewRequest("GET", "/sse", nil)
	req3.RemoteAddr = ip + ":1234"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec3.Code)
	}
	if rec3.Header().Get("Retry-After") != "1" {
		t.Errorf("expected Retry-After header '1', got %s", rec3.Header().Get("Retry-After"))
	}
}

func TestLoginBruteForceProtector_ExponentialBackoff(t *testing.T) {
	protector := NewLoginBruteForceProtector(5, 30)
	ip := "10.10.10.10"

	// First 4 failures should NOT trigger lockout
	for i := 1; i <= 4; i++ {
		locked, _ := protector.RecordFailure(ip)
		if locked {
			t.Fatalf("Attempt %d should not be locked", i)
		}
		isLocked, _ := protector.IsLocked(ip)
		if isLocked {
			t.Fatalf("IsLocked should be false on attempt %d", i)
		}
	}

	// 5th failure must trigger exponential backoff (2s)
	locked, waitSec := protector.RecordFailure(ip)
	if !locked {
		t.Fatal("Attempt 5 must trigger lockout")
	}
	if waitSec != 2 {
		t.Errorf("expected 2s backoff, got %d", waitSec)
	}

	isLocked, remaining := protector.IsLocked(ip)
	if !isLocked || remaining <= 0 {
		t.Fatalf("IsLocked must be true after 5th failure, got %v (%d sec)", isLocked, remaining)
	}

	// 6th failure should escalate backoff (4s)
	locked, waitSec = protector.RecordFailure(ip)
	if !locked || waitSec != 4 {
		t.Errorf("expected 4s backoff on 6th failure, got locked=%v wait=%d", locked, waitSec)
	}
}

func TestLoginBruteForceProtector_SuccessReset(t *testing.T) {
	protector := NewLoginBruteForceProtector(5, 30)
	ip := "10.10.10.20"

	// Record 4 failures
	for i := 0; i < 4; i++ {
		protector.RecordFailure(ip)
	}

	// Successful login resets state
	protector.RecordSuccess(ip)

	// Now another failure should be attempt 1, NOT attempt 5
	locked, _ := protector.RecordFailure(ip)
	if locked {
		t.Fatal("Attempt after successful login reset should not be locked")
	}
}

func BenchmarkTokenBucketLimiter_HighConcurrency(t *testing.B) {
	limiter := NewTokenBucketLimiter(1000000.0, 5000000)
	ip := "192.168.1.1"

	t.ResetTimer()
	t.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = limiter.Allow(ip)
		}
	})
}

func BenchmarkLoginBruteForceProtector(t *testing.B) {
	protector := NewLoginBruteForceProtector(5, 30)
	ip := "192.168.1.2"

	t.ResetTimer()
	t.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = protector.IsLocked(ip)
		}
	})
}

func BenchmarkClientIP_SocketExtraction(b *testing.B) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.150:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	req.Header.Set("X-Real-IP", "203.0.113.195")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClientIP(req)
	}
}
