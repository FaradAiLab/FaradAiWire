package proxy

import (
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestContextExtractor_UntrustedClientDowngrade(t *testing.T) {
	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
		TrustedProxies: []string{"10.0.0.0/8"},
	}
	extractor := NewContextExtractor(cfg)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678" // Untrusted IP outside 10.0.0.0/8
	req.Header.Set("X-User-ID", "attacker-user")
	req.Header.Set("X-User-Role", "Admin")

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Customer" {
		t.Errorf("expected role 'Customer' after downgrade, got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "guest-customer" {
		t.Errorf("expected userID 'guest-customer' after downgrade, got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_QueryParamFallbackEliminated(t *testing.T) {
	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
		TrustedProxies: []string{"127.0.0.1/32"},
	}
	extractor := NewContextExtractor(cfg)

	// Even from a trusted IP, query parameter overrides should NOT be used
	req := httptest.NewRequest("POST", "/message?role=Admin&user_id=spoofed-admin", nil)
	req.RemoteAddr = "127.0.0.1:50000"

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Customer" {
		t.Errorf("expected role 'Customer' when no headers provided (query params ignored), got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "guest-customer" {
		t.Errorf("expected userID 'guest-customer' (query params ignored), got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_TrustedProxiesCIDR(t *testing.T) {
	cfg := config.UserContextConfig{
		FallbackRole: "Guest",
		FallbackUser: "anonymous",
		TrustedProxies: []string{"10.244.0.0/16", "172.16.0.0/12"},
	}
	extractor := NewContextExtractor(cfg)

	// Request from IP inside 10.244.0.0/16
	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "10.244.5.12:43210"
	req.Header.Set("X-User-ID", "soc-lead-1")
	req.Header.Set("X-User-Role", "SOC_Lead")

	uCtx := extractor.Extract(req)
	if uCtx.Role != "SOC_Lead" {
		t.Errorf("expected role 'SOC_Lead', got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "soc-lead-1" {
		t.Errorf("expected userID 'soc-lead-1', got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_TrustedProxiesSingleIP(t *testing.T) {
	cfg := config.UserContextConfig{
		FallbackRole: "Guest",
		FallbackUser: "anonymous",
		TrustedProxies: []string{"192.168.1.50", "::1"},
	}
	extractor := NewContextExtractor(cfg)

	// IPv4 single IP match
	req1 := httptest.NewRequest("POST", "/message", nil)
	req1.RemoteAddr = "192.168.1.50:8080"
	req1.Header.Set("X-User-ID", "ir-agent")
	req1.Header.Set("X-User-Role", "Incident_Responder")

	uCtx1 := extractor.Extract(req1)
	if uCtx1.Role != "Incident_Responder" || uCtx1.UserID != "ir-agent" {
		t.Errorf("expected Incident_Responder / ir-agent, got %s / %s", uCtx1.Role, uCtx1.UserID)
	}

	// IPv6 single IP match
	req2 := httptest.NewRequest("POST", "/message", nil)
	req2.RemoteAddr = "[::1]:54321"
	req2.Header.Set("X-User-ID", "dev-user")
	req2.Header.Set("X-User-Role", "Developer")

	uCtx2 := extractor.Extract(req2)
	if uCtx2.Role != "Developer" || uCtx2.UserID != "dev-user" {
		t.Errorf("expected Developer / dev-user, got %s / %s", uCtx2.Role, uCtx2.UserID)
	}
}

func TestContextExtractor_HMACSignature_ValidSeparateHeaders(t *testing.T) {
	secret := "test-secret-key-12345"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: secret,
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	userID := "alice-admin"
	role := "Admin"

	sig := ComputeHMACSignature([]byte(secret), tsStr, userID, role)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678" // Untrusted IP
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Admin" {
		t.Errorf("expected role 'Admin', got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "alice-admin" {
		t.Errorf("expected userID 'alice-admin', got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_HMACSignature_ValidCombinedHeader(t *testing.T) {
	secret := "test-secret-key-12345"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: secret,
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	userID := "alice-admin"
	role := "Admin"

	sig := ComputeHMACSignature([]byte(secret), tsStr, userID, role)

	// Format: t=...,v1=...
	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Signature", fmt.Sprintf("t=%s,v1=%s", tsStr, sig))

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Admin" || uCtx.UserID != "alice-admin" {
		t.Errorf("expected Admin / alice-admin with combined header, got %s / %s", uCtx.Role, uCtx.UserID)
	}

	// Format: <timestamp>.<signature>
	req2 := httptest.NewRequest("POST", "/message", nil)
	req2.RemoteAddr = "198.51.100.23:45678"
	req2.Header.Set("X-User-ID", userID)
	req2.Header.Set("X-User-Role", role)
	req2.Header.Set("X-FaradAiWire-Signature", fmt.Sprintf("%s.%s", tsStr, sig))

	uCtx2 := extractor.Extract(req2)
	if uCtx2.Role != "Admin" || uCtx2.UserID != "alice-admin" {
		t.Errorf("expected Admin / alice-admin with dot format, got %s / %s", uCtx2.Role, uCtx2.UserID)
	}
}

func TestContextExtractor_HMACSignature_ExpiredTimestamp(t *testing.T) {
	secret := "test-secret-key-12345"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: secret,
	}
	extractor := NewContextExtractor(cfg)

	// 10 minutes in the past
	expiredTime := time.Now().Add(-10 * time.Minute).Unix()
	tsStr := strconv.FormatInt(expiredTime, 10)
	userID := "alice-admin"
	role := "Admin"

	sig := ComputeHMACSignature([]byte(secret), tsStr, userID, role)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Customer" || uCtx.UserID != "guest-customer" {
		t.Errorf("expected downgraded role Customer / guest-customer for expired timestamp, got %s / %s", uCtx.Role, uCtx.UserID)
	}
}

func TestContextExtractor_HMACSignature_TamperedPayload(t *testing.T) {
	secret := "test-secret-key-12345"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: secret,
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)

	// Attacker calculates HMAC for Customer role, but alters X-User-Role to Admin
	sig := ComputeHMACSignature([]byte(secret), tsStr, "alice-admin", "Customer")

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", "alice-admin")
	req.Header.Set("X-User-Role", "Admin") // Tampered role!
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Customer" || uCtx.UserID != "guest-customer" {
		t.Errorf("expected downgraded role Customer / guest-customer on tampered signature, got %s / %s", uCtx.Role, uCtx.UserID)
	}
}

func TestContextExtractor_HMACSignature_WrongSecret(t *testing.T) {
	serverSecret := "correct-server-secret"
	clientSecret := "wrong-client-secret"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: serverSecret,
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	userID := "alice-admin"
	role := "Admin"

	sig := ComputeHMACSignature([]byte(clientSecret), tsStr, userID, role)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Customer" || uCtx.UserID != "guest-customer" {
		t.Errorf("expected downgraded role Customer / guest-customer for wrong secret, got %s / %s", uCtx.Role, uCtx.UserID)
	}
}

func TestContextExtractor_EnvVarExpansion(t *testing.T) {
	os.Setenv("DYNAMIC_HMAC_SECRET_TEST", "dynamic-secret-val-999")
	defer os.Unsetenv("DYNAMIC_HMAC_SECRET_TEST")

	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: "${DYNAMIC_HMAC_SECRET_TEST}",
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	userID := "env-admin"
	role := "Admin"

	sig := ComputeHMACSignature([]byte("dynamic-secret-val-999"), tsStr, userID, role)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Admin" || uCtx.UserID != "env-admin" {
		t.Errorf("expected Admin / env-admin with env var secret, got %s / %s", uCtx.Role, uCtx.UserID)
	}
}

func TestContextExtractor_CustomHeaderNames(t *testing.T) {
	cfg := config.UserContextConfig{
		RoleHeader:     "X-Custom-Role",
		UserHeader:     "X-Custom-User",
		FallbackRole:   "Guest",
		FallbackUser:   "anon",
		TrustedProxies: []string{"10.0.0.0/8"},
	}
	extractor := NewContextExtractor(cfg)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Custom-User", "custom-user-1")
	req.Header.Set("X-Custom-Role", "Auditor")

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Auditor" || uCtx.UserID != "custom-user-1" {
		t.Errorf("expected Auditor / custom-user-1 with custom headers, got %s / %s", uCtx.Role, uCtx.UserID)
	}
}

func TestContextExtractor_BearerAuth_ValidKey(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	rawToken, _, err := keyStore.GenerateKey("Cursor Local Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}
	extractor := NewContextExtractor(cfg, keyStore)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678" // Untrusted IP
	req.Header.Set("Authorization", "Bearer "+rawToken)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Developer" {
		t.Errorf("expected role 'Developer', got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "Cursor Local Agent" {
		t.Errorf("expected userID 'Cursor Local Agent', got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_XAPIKey_ValidKey(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	rawToken, _, err := keyStore.GenerateKey("Claude Desktop Agent", "Admin")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}
	extractor := NewContextExtractor(cfg, keyStore)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-API-Key", rawToken)

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Admin" {
		t.Errorf("expected role 'Admin', got '%s'", uCtx.Role)
	}
	if uCtx.UserID != "Claude Desktop Agent" {
		t.Errorf("expected userID 'Claude Desktop Agent', got '%s'", uCtx.UserID)
	}
}

func TestContextExtractor_BearerAuth_InvalidKey(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	_, _, err := keyStore.GenerateKey("Valid Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}
	extractor := NewContextExtractor(cfg, keyStore)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("Authorization", "Bearer faw_live_invalid_corrupted_key_token")
	req.Header.Set("X-User-Role", "Admin") // Attacker attempting spoof

	uCtx, err := extractor.Authenticate(req)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for invalid key, got %v", err)
	}
	if uCtx != nil {
		t.Errorf("expected nil UserContext for invalid key, got '%+v'", uCtx)
	}
	if extractor.Extract(req) != nil {
		t.Errorf("expected Extract() to return nil for invalid key")
	}
}

func TestContextExtractor_BearerAuth_RevokedKey(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	rawToken, record, err := keyStore.GenerateKey("Compromised Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err = keyStore.RevokeKey(record.ID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}
	extractor := NewContextExtractor(cfg, keyStore)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("Authorization", "Bearer "+rawToken)

	uCtx, err := extractor.Authenticate(req)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for revoked key, got %v", err)
	}
	if uCtx != nil {
		t.Errorf("expected nil UserContext for revoked key, got '%+v'", uCtx)
	}
	if extractor.Extract(req) != nil {
		t.Errorf("expected Extract() to return nil for revoked key")
	}
}

func TestContextExtractor_BearerAuth_RoleSpoofingPrevented(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	rawToken, _, err := keyStore.GenerateKey("Dev Key", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := config.UserContextConfig{
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}
	extractor := NewContextExtractor(cfg, keyStore)

	// Caller has Developer key but attempts to spoof Admin role via X-User-Role header
	req := httptest.NewRequest("POST", "/message", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("X-User-Role", "Admin")

	uCtx := extractor.Extract(req)
	if uCtx.Role != "Developer" {
		t.Errorf("expected key role 'Developer' to override spoofed 'Admin' header, got '%s'", uCtx.Role)
	}
}

func BenchmarkContextExtractor_Extract_TrustedIP(b *testing.B) {
	cfg := config.UserContextConfig{
		FallbackRole:   "Customer",
		FallbackUser:   "guest-customer",
		TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}
	extractor := NewContextExtractor(cfg)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "10.12.34.56:54321"
	req.Header.Set("X-User-ID", "bench-user")
	req.Header.Set("X-User-Role", "Developer")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(req)
	}
}

func BenchmarkContextExtractor_Extract_HMACSignature(b *testing.B) {
	secret := "benchmarking-hmac-secret-key-12345"
	cfg := config.UserContextConfig{
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		ContextHMACSecret: secret,
	}
	extractor := NewContextExtractor(cfg)

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	userID := "bench-user"
	role := "Developer"
	sig := ComputeHMACSignature([]byte(secret), tsStr, userID, role)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "198.51.100.23:45678"
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("X-User-Role", role)
	req.Header.Set("X-FaradAiWire-Timestamp", tsStr)
	req.Header.Set("X-FaradAiWire-Signature", sig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(req)
	}
}
