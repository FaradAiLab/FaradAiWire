package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestSSEProxy_IngressRateLimiting(t *testing.T) {
	enabled := true
	secCfg := config.SecurityConfig{
		RateLimiting: config.HTTPRateLimitConfig{
			Enabled: &enabled,
			Rate:    1.0, // 1 req/sec
			Burst:   3,   // Max burst capacity of 3
		},
	}

	pipeline := filter.NewPipeline(nil)
	userCtxCfg := config.UserContextConfig{}
	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", pipeline, nil, nil, userCtxCfg, secCfg)
	handler := proxy.Handler()

	clientIP := "203.0.113.10:54321"

	// 1. Send 3 requests (burst allowed)
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sse", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// /sse may return 200 or 400 depending on backend, but must NOT be 429
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d within burst was unexpectedly rate limited (429)", i)
		}
	}

	// 2. 4th request from same IP exceeds burst -> must return 429 Too Many Requests
	reqRateLimited := httptest.NewRequest(http.MethodPost, "/message", strings.NewReader(`{}`))
	reqRateLimited.RemoteAddr = clientIP
	recRateLimited := httptest.NewRecorder()
	handler.ServeHTTP(recRateLimited, reqRateLimited)

	if recRateLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on 4th request, got %d", recRateLimited.Code)
	}
	if recRateLimited.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After: 1 header, got %q", recRateLimited.Header().Get("Retry-After"))
	}

	var errBody map[string]string
	if err := json.Unmarshal(recRateLimited.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("failed to parse rate limit response JSON: %v", err)
	}
	if errBody["error"] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected RATE_LIMIT_EXCEEDED, got %q", errBody["error"])
	}

	// 3. Different client IP is NOT rate limited
	otherIP := "203.0.113.20:54321"
	reqOther := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqOther.RemoteAddr = otherIP
	recOther := httptest.NewRecorder()
	handler.ServeHTTP(recOther, reqOther)

	if recOther.Code == http.StatusTooManyRequests {
		t.Fatalf("separate client IP %s was unexpectedly rate limited", otherIP)
	}
}

func TestSSEProxy_IngressRateLimiting_SpoofedXFFIgnored(t *testing.T) {
	enabled := true
	secCfg := config.SecurityConfig{
		RateLimiting: config.HTTPRateLimitConfig{
			Enabled: &enabled,
			Rate:    1.0, // 1 req/sec
			Burst:   3,   // Max burst capacity of 3
		},
	}

	pipeline := filter.NewPipeline(nil)
	userCtxCfg := config.UserContextConfig{}
	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", pipeline, nil, nil, userCtxCfg, secCfg)
	handler := proxy.Handler()

	socketIP := "198.51.100.50:54321"

	// 1. Send 3 requests within burst capacity, each presenting spoofed proxy headers
	spoofedHeaders := []string{"10.0.0.1", "172.16.0.2", "192.168.1.3"}
	for i, spoofIP := range spoofedHeaders {
		req := httptest.NewRequest(http.MethodGet, "/sse", nil)
		req.RemoteAddr = socketIP
		req.Header.Set("X-Forwarded-For", spoofIP)
		req.Header.Set("X-Real-IP", spoofIP)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d within burst was unexpectedly rate limited (429)", i+1)
		}
	}

	// 2. 4th request from same socket IP with a 4th spoofed header must be rate limited (HTTP 429)
	reqSpoofed4 := httptest.NewRequest(http.MethodPost, "/message", strings.NewReader(`{}`))
	reqSpoofed4.RemoteAddr = socketIP
	reqSpoofed4.Header.Set("X-Forwarded-For", "203.0.113.99")
	reqSpoofed4.Header.Set("X-Real-IP", "203.0.113.99")
	recSpoofed4 := httptest.NewRecorder()
	handler.ServeHTTP(recSpoofed4, reqSpoofed4)

	if recSpoofed4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 on 4th request despite spoofed XFF, got %d", recSpoofed4.Code)
	}

	var errBody map[string]string
	if err := json.Unmarshal(recSpoofed4.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("failed to parse rate limit response JSON: %v", err)
	}
	if errBody["error"] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected RATE_LIMIT_EXCEEDED, got %q", errBody["error"])
	}
}

func TestSSEProxy_ProfileHeader(t *testing.T) {
	// 1. Unit tests for extractAgentName precedence
	// Case A: Canonical X-FaradAiWire-Profile header
	reqA := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqA.Header.Set("X-FaradAiWire-Profile", "security-auditor")
	reqA.Header.Set("X-FaradAiWire-Agent-Name", "fallback-agent")
	if got := extractAgentName(reqA); got != "security-auditor" {
		t.Fatalf("expected X-FaradAiWire-Profile header to take highest precedence, got %q", got)
	}

	// Case B: Query parameter ?profile=
	reqB := httptest.NewRequest(http.MethodGet, "/sse?profile=code-reviewer", nil)
	reqB.Header.Set("X-FaradAiWire-Agent-Name", "fallback-agent")
	if got := extractAgentName(reqB); got != "code-reviewer" {
		t.Fatalf("expected ?profile= query param to take precedence over legacy agent header, got %q", got)
	}

	// Case C: Legacy X-FaradAiWire-Agent-Name header fallback
	reqC := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqC.Header.Set("X-FaradAiWire-Agent-Name", "legacy-agent")
	if got := extractAgentName(reqC); got != "legacy-agent" {
		t.Fatalf("expected fallback to X-FaradAiWire-Agent-Name, got %q", got)
	}

	// Case D: Legacy query param ?agent=
	reqD := httptest.NewRequest(http.MethodGet, "/sse?agent=legacy-query-agent", nil)
	if got := extractAgentName(reqD); got != "legacy-query-agent" {
		t.Fatalf("expected fallback to ?agent= query param, got %q", got)
	}

	// Case E: Path fallback /sse/{name}
	reqE := httptest.NewRequest(http.MethodGet, "/sse/path-profile/message", nil)
	if got := extractAgentName(reqE); got != "path-profile" {
		t.Fatalf("expected fallback to path agent extraction, got %q", got)
	}

	// 2. Integration test with SSEProxy routing and checkAggregatedAgent
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "dev-profile", "current"), 0755)
	_ = os.MkdirAll(filepath.Join(agentDir, "prod-profile", "current"), 0755)

	devCfg := agent.RouteConfig{
		AgentName:   "dev-profile",
		RoutingMode: "aggregated",
	}
	prodCfg := agent.RouteConfig{
		AgentName:   "prod-profile",
		RoutingMode: "aggregated",
	}
	devBytes, _ := json.Marshal(devCfg)
	prodBytes, _ := json.Marshal(prodCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "dev-profile", "current", "config.json"), devBytes, 0644)
	_ = os.WriteFile(filepath.Join(agentDir, "prod-profile", "current", "config.json"), prodBytes, 0644)

	proxy := NewSSEProxy(0, "", nil, agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})

	// Request to /sse with X-FaradAiWire-Profile header
	reqHeader := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqHeader.Header.Set("X-FaradAiWire-Profile", "dev-profile")
	resolved, isAgg, err := proxy.checkAggregatedAgent(reqHeader)
	if err != nil {
		t.Fatalf("expected checkAggregatedAgent to succeed with X-FaradAiWire-Profile, got %v", err)
	}
	if !isAgg || resolved != "dev-profile" {
		t.Fatalf("expected resolved agent 'dev-profile', got %q (isAgg=%v)", resolved, isAgg)
	}

	// Request to /sse?profile=prod-profile
	reqQuery := httptest.NewRequest(http.MethodGet, "/sse?profile=prod-profile", nil)
	resolvedQ, isAggQ, errQ := proxy.checkAggregatedAgent(reqQuery)
	if errQ != nil {
		t.Fatalf("expected checkAggregatedAgent to succeed with ?profile=, got %v", errQ)
	}
	if !isAggQ || resolvedQ != "prod-profile" {
		t.Fatalf("expected resolved agent 'prod-profile', got %q (isAgg=%v)", resolvedQ, isAggQ)
	}

	// Fail-closed authorization: API key scoped to dev-profile cannot access prod-profile via header
	reqForbidden := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqForbidden.Header.Set("X-FaradAiWire-Profile", "prod-profile")
	reqForbidden = reqForbidden.WithContext(context.WithValue(reqForbidden.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "alice",
		Role:      "Developer",
		AgentName: "dev-profile",
	}))
	_, _, errForbidden := proxy.checkAggregatedAgent(reqForbidden)
	if errForbidden == nil {
		t.Fatalf("expected AGENT_ACCESS_DENIED when key scoped to dev-profile requests prod-profile")
	}
	if !strings.Contains(errForbidden.Error(), "AGENT_ACCESS_DENIED") {
		t.Fatalf("expected AGENT_ACCESS_DENIED, got: %v", errForbidden)
	}
}
