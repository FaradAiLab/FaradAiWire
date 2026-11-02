package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientIP extracts the remote client's IP address strictly from the network socket (r.RemoteAddr).
// Disregards spoofable proxy headers (X-Forwarded-For, X-Real-IP) in standalone mode to prevent
// trivial rate limiter bypasses (SEC-016 / SPEC-SEC-003).
func ClientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

// clientBucket tracks token-bucket state for a specific client IP.
type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

// TokenBucketLimiter provides thread-safe, memory-bounded token-bucket rate limiting per IP.
type TokenBucketLimiter struct {
	rate      float64
	burst     float64
	mu        sync.Mutex
	buckets   map[string]*clientBucket
	ttl       time.Duration
	lastClean time.Time
}

// NewTokenBucketLimiter creates a TokenBucketLimiter with a refill rate (tokens/sec) and burst capacity.
func NewTokenBucketLimiter(rate float64, burst int) *TokenBucketLimiter {
	if rate <= 0 {
		rate = 100.0
	}
	if burst <= 0 {
		burst = 200
	}
	return &TokenBucketLimiter{
		rate:      rate,
		burst:     float64(burst),
		buckets:   make(map[string]*clientBucket),
		ttl:       5 * time.Minute,
		lastClean: time.Now(),
	}
}

// Allow reports whether a request from the given IP is permitted under the rate limit.
func (l *TokenBucketLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Periodic eviction of inactive client buckets every 1 minute
	if now.Sub(l.lastClean) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.lastRefill) > l.ttl {
				delete(l.buckets, k)
			}
		}
		l.lastClean = now
	}

	b, exists := l.buckets[ip]
	if !exists {
		l.buckets[ip] = &clientBucket{
			tokens:     l.burst - 1.0,
			lastRefill: now,
		}
		return true
	}

	// Refill tokens based on elapsed duration
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// HTTPRateLimit returns an HTTP middleware enforcing token-bucket rate limiting per client IP.
func HTTPRateLimit(rate float64, burst int) func(http.Handler) http.Handler {
	limiter := NewTokenBucketLimiter(rate, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			if !limiter.Allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "RATE_LIMIT_EXCEEDED",
					"message": "Too many requests, please slow down.",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// loginAttempt tracks consecutive authentication failures and lockout expirations.
type loginAttempt struct {
	failedCount  int
	lockoutUntil time.Time
	lastAttempt  time.Time
}

// LoginBruteForceProtector enforces exponential backoff and lockout thresholds against brute-force attacks.
type LoginBruteForceProtector struct {
	mu          sync.Mutex
	attempts    map[string]*loginAttempt
	maxAttempts int
	lockoutSec  int
	lastClean   time.Time
}

// NewLoginBruteForceProtector constructs a LoginBruteForceProtector.
func NewLoginBruteForceProtector(maxAttempts int, lockoutSec int) *LoginBruteForceProtector {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockoutSec <= 0 {
		lockoutSec = 60
	}
	return &LoginBruteForceProtector{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: maxAttempts,
		lockoutSec:  lockoutSec,
		lastClean:   time.Now(),
	}
}

// IsLocked checks whether the IP is currently locked out or in an exponential backoff delay.
func (p *LoginBruteForceProtector) IsLocked(ip string) (bool, int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	att, exists := p.attempts[ip]
	if !exists {
		return false, 0
	}

	if att.lockoutUntil.After(now) {
		remaining := int(att.lockoutUntil.Sub(now).Seconds()) + 1
		return true, remaining
	}

	return false, 0
}

// RecordFailure records a failed authentication attempt and returns whether the IP is now locked out.
func (p *LoginBruteForceProtector) RecordFailure(ip string) (bool, int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Periodic cleanup of records older than 10 minutes
	if now.Sub(p.lastClean) > 2*time.Minute {
		for k, a := range p.attempts {
			if now.Sub(a.lastAttempt) > 10*time.Minute && now.After(a.lockoutUntil) {
				delete(p.attempts, k)
			}
		}
		p.lastClean = now
	}

	att, exists := p.attempts[ip]
	if !exists {
		att = &loginAttempt{}
		p.attempts[ip] = att
	}

	att.failedCount++
	att.lastAttempt = now

	if att.failedCount >= p.maxAttempts {
		// Exponential backoff: 2s, 4s, 8s, 16s, 32s, up to p.lockoutSec
		exponent := att.failedCount - p.maxAttempts
		if exponent > 6 {
			exponent = 6
		}
		backoff := 2 << exponent
		if backoff > p.lockoutSec {
			backoff = p.lockoutSec
		}
		att.lockoutUntil = now.Add(time.Duration(backoff) * time.Second)
		return true, backoff
	}

	return false, 0
}

// RecordSuccess clears any failure records for the IP upon successful authentication.
func (p *LoginBruteForceProtector) RecordSuccess(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.attempts, ip)
}

// WriteLockoutResponse writes standard 429 Too Many Requests response with Retry-After header.
func WriteLockoutResponse(w http.ResponseWriter, retryAfterSec int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "TOO_MANY_FAILED_ATTEMPTS",
		"message": fmt.Sprintf("Too many failed login attempts. Account temporarily locked for %d seconds.", retryAfterSec),
	})
}
