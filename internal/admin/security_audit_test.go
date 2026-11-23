package admin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

type spySecurityAuditLogger struct {
	mu     sync.Mutex
	events []*filter.SecurityAuditEvent
}

func (s *spySecurityAuditLogger) LogSecurityEvent(event *filter.SecurityAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *spySecurityAuditLogger) Events() []*filter.SecurityAuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*filter.SecurityAuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

func (s *spySecurityAuditLogger) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

type spyToolAuditLogger struct {
	mu     sync.Mutex
	events []*filter.AuditEvent
}

func (s *spyToolAuditLogger) LogEvent(event *filter.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *spyToolAuditLogger) Events() []*filter.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*filter.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidateAdminCredential_ReturnsActorID(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "env-super-secret-admin-token")

	ks := auth.NewMemoryKeyStore()
	adminRaw, adminRec, err := ks.GenerateKey("primary-admin", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Admin): %v", err)
	}
	devRaw, devRec, err := ks.GenerateKey("scoped-dev", "Developer", "agent-a")
	if err != nil {
		t.Fatalf("GenerateKey(Developer): %v", err)
	}

	srv := NewAdminServer(AdminDependencies{
		Config:   &config.Config{RuntimeMode: config.RuntimeModeStandalone},
		KeyStore: ks,
	})

	cases := []struct {
		name        string
		token       string
		wantValid   bool
		wantIsAdmin bool
		wantActorID string
	}{
		{
			name:        "env admin token",
			token:       "env-super-secret-admin-token",
			wantValid:   true,
			wantIsAdmin: true,
			wantActorID: "env:admin_token",
		},
		{
			name:        "stored admin api key returns key ID",
			token:       adminRaw,
			wantValid:   true,
			wantIsAdmin: true,
			wantActorID: adminRec.ID,
		},
		{
			name:        "stored developer api key returns key ID and non-admin",
			token:       devRaw,
			wantValid:   true,
			wantIsAdmin: false,
			wantActorID: devRec.ID,
		},
		{
			name:        "invalid token",
			token:       "faw_live_bogus",
			wantValid:   false,
			wantIsAdmin: false,
			wantActorID: "",
		},
		{
			name:        "empty token",
			token:       "   ",
			wantValid:   false,
			wantIsAdmin: false,
			wantActorID: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid, isAdmin, actorID := srv.validateAdminCredential(tc.token)
			if valid != tc.wantValid || isAdmin != tc.wantIsAdmin || actorID != tc.wantActorID {
				t.Fatalf("validateAdminCredential() = (%v, %v, %q), want (%v, %v, %q)",
					valid, isAdmin, actorID, tc.wantValid, tc.wantIsAdmin, tc.wantActorID)
			}
		})
	}
}

func TestAdminSessionCookie_ActorBindingAndLegacyCompatibility(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "")

	ks, err := auth.NewFileKeyStore(filepath.Join(t.TempDir(), "keys", "api_keys.json"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	_, adminRec, err := ks.GenerateKey("admin-one", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	srv := NewAdminServer(AdminDependencies{
		Config:   &config.Config{RuntimeMode: config.RuntimeModeStandalone, AdminHost: "0.0.0.0"},
		KeyStore: ks,
	})

	// 1. New 3-part format: expHex.actorID.sigHex
	val, ok := srv.signAdminSessionCookieValue(adminRec.ID)
	if !ok || strings.Count(val, ".") < 2 {
		t.Fatalf("expected 3-part session cookie value, got ok=%v val=%q", ok, val)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: val})
	gotActor, valid := srv.extractValidAdminSessionCookie(req)
	if !valid || gotActor != adminRec.ID {
		t.Fatalf("extractValidAdminSessionCookie() = (%q, %v), want (%q, true)", gotActor, valid, adminRec.ID)
	}

	// 2. Tampering with actorID in cookie fails HMAC verification
	firstDot := strings.IndexByte(val, '.')
	lastDot := strings.LastIndexByte(val, '.')
	tampered := val[:firstDot+1] + "env:admin_token" + val[lastDot:]
	tamperReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	tamperReq.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: tampered})
	if actor, ok := srv.extractValidAdminSessionCookie(tamperReq); ok {
		t.Fatalf("expected tampered actor cookie to be rejected, got actor=%q", actor)
	}

	// 3. Legacy 2-part format (expHex.sigHex signed only over expHex) still accepted
	secrets := srv.deriveAdminSessionSecrets()
	if len(secrets) == 0 {
		t.Fatal("expected derived admin session secret")
	}
	expHex := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 16)
	mac := hmac.New(sha256.New, secrets[0])
	_, _ = mac.Write([]byte(expHex))
	legacyVal := expHex + "." + hex.EncodeToString(mac.Sum(nil))

	legacyReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	legacyReq.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: legacyVal})
	if legacyActor, ok := srv.extractValidAdminSessionCookie(legacyReq); !ok || legacyActor == "" {
		t.Fatalf("expected legacy 2-part cookie to remain valid with fallback actor, got (%q, %v)", legacyActor, ok)
	}
}

func TestAdminSecurity_VerifiedActorIgnoresSpoofedHeaders(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "")

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	ks := auth.NewMemoryKeyStore()
	adminRaw, adminRec, err := ks.GenerateKey("admin-actor", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	secSpy := &spySecurityAuditLogger{}
	toolSpy := &spyToolAuditLogger{}

	// Non-loopback server requiring admin auth
	nonLoopbackSrv := NewAdminServer(AdminDependencies{
		Config:               &config.Config{RuntimeMode: config.RuntimeModeStandalone, AdminHost: "0.0.0.0", AdminPort: 19415},
		ReloadFunc:           func() error { return nil },
		KeyStore:             ks,
		SettingsStore:        store,
		SettingsCache:        settings.NewCache(settings.DefaultOperationalSettings()),
		AuditLoggers:         []AuditEventLogger{toolSpy},
		SecurityAuditLoggers: []SecurityAuditEventLogger{secSpy},
	})
	h := nonLoopbackSrv.Handler()

	// Case A: Bearer token + forged X-User-ID/X-User-Role headers -> must record adminRec.ID
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:19415/admin/settings", strings.NewReader(`{"settings":{"maintenance.audit_export_max_rows":10000}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminRaw)
	req.Header.Set("X-User-ID", "attacker-spoofed")
	req.Header.Set("X-User-Role", "super-duper")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/settings (Bearer) = %d: %s", rec.Code, rec.Body.String())
	}
	bearerEvents := secSpy.Events()
	if len(bearerEvents) != 1 || bearerEvents[0].ActorID != adminRec.ID || bearerEvents[0].ActorRole != "admin" {
		t.Fatalf("expected actor_id=%q and actor_role=admin for Bearer settings mutation, got %+v", adminRec.ID, bearerEvents)
	}

	// Case B: Session cookie + forged X-User-ID header -> must record adminRec.ID
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19415/admin/auth/session", strings.NewReader(`{"token":"`+adminRaw+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /admin/auth/session = %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == adminSessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected admin session cookie")
	}

	secSpy.Reset()
	reqCookie := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19415/admin/reload", strings.NewReader(`{}`))
	reqCookie.Header.Set("Content-Type", "application/json")
	reqCookie.AddCookie(sessionCookie)
	reqCookie.Header.Set("X-User-ID", "cookie-spoofed")
	recCookie := httptest.NewRecorder()
	h.ServeHTTP(recCookie, reqCookie)
	if recCookie.Code != http.StatusOK {
		t.Fatalf("POST /admin/reload (Cookie) = %d: %s", recCookie.Code, recCookie.Body.String())
	}

	// Verify both Bearer and Cookie recorded verified adminRec.ID, never spoofed headers, and 0 tool_audit_logs
	if gotTools := len(toolSpy.Events()); gotTools != 0 {
		t.Fatalf("expected 0 tool_audit_logs for admin mutations, got %d", gotTools)
	}
	cookieEvents := secSpy.Events()
	if len(cookieEvents) != 1 || cookieEvents[0].ActorID != adminRec.ID {
		t.Fatalf("expected actor_id=%q for cookie reload, got %+v", adminRec.ID, cookieEvents)
	}

	// Case C: Loopback passwordless mode preserves ADR-0028 access with actor local-operator, ignoring X-User-ID
	loopSpy := &spySecurityAuditLogger{}
	loopSrv := NewAdminServer(AdminDependencies{
		Config:               &config.Config{RuntimeMode: config.RuntimeModeStandalone, AdminHost: "127.0.0.1", AdminPort: 19415},
		ReloadFunc:           func() error { return nil },
		SecurityAuditLoggers: []SecurityAuditEventLogger{loopSpy},
	})
	loopReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19415/admin/reload", strings.NewReader(`{}`))
	loopReq.Header.Set("Content-Type", "application/json")
	loopReq.Header.Set("X-User-ID", "header-spoof")
	loopRec := httptest.NewRecorder()
	loopSrv.Handler().ServeHTTP(loopRec, loopReq)
	if loopRec.Code != http.StatusOK {
		t.Fatalf("loopback POST /admin/reload = %d: %s", loopRec.Code, loopRec.Body.String())
	}
	loopEvents := loopSpy.Events()
	if len(loopEvents) != 1 || loopEvents[0].ActorID != "local-operator" {
		t.Fatalf("expected loopback actor_id='local-operator', got %+v", loopEvents)
	}
}

func TestAdminSecurity_BearerBruteForceLockoutAndAudit(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "")

	ks := auth.NewMemoryKeyStore()
	adminRaw, _, err := ks.GenerateKey("admin-key", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	secSpy := &spySecurityAuditLogger{}
	srv := NewAdminServer(AdminDependencies{
		Config:               &config.Config{RuntimeMode: config.RuntimeModeStandalone, AdminHost: "0.0.0.0", AdminPort: 19415},
		KeyStore:             ks,
		SecurityAuditLoggers: []SecurityAuditEventLogger{secSpy},
	})
	h := srv.Handler()

	const badToken = "faw_live_totally_invalid_secret_token"
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19415/admin/status", nil)
		req.RemoteAddr = "198.51.100.77:40000"
		req.Header.Set("Authorization", "Bearer "+badToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i+1, rec.Code)
		}
	}

	// 6th attempt even with valid Admin Bearer token MUST be rejected with 429 TOO_MANY_ATTEMPTS
	lockedReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19415/admin/status", nil)
	lockedReq.RemoteAddr = "198.51.100.77:40001"
	lockedReq.Header.Set("Authorization", "Bearer "+adminRaw)
	lockedRec := httptest.NewRecorder()
	h.ServeHTTP(lockedRec, lockedReq)
	if lockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt status=%d, want 429 (%s)", lockedRec.Code, lockedRec.Body.String())
	}
	if !strings.Contains(lockedRec.Body.String(), "TOO_MANY_ATTEMPTS") {
		t.Fatalf("expected TOO_MANY_ATTEMPTS error body, got %s", lockedRec.Body.String())
	}

	// Independent IP still succeeds
	okReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19415/admin/status", nil)
	okReq.RemoteAddr = "198.51.100.88:40002"
	okReq.Header.Set("Authorization", "Bearer "+adminRaw)
	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("independent IP Bearer = %d, want 200", okRec.Code)
	}

	var failedCount, lockoutCount int
	for _, ev := range secSpy.Events() {
		rawBlob, _ := json.Marshal(ev)
		if strings.Contains(string(rawBlob), badToken) || strings.Contains(string(rawBlob), adminRaw) {
			t.Fatalf("security audit event leaked raw credential: %s", string(rawBlob))
		}
		if ev.EventType == "admin_auth_failed" {
			failedCount++
		}
		if ev.EventType == "admin_auth_lockout" && ev.Outcome == "locked" {
			lockoutCount++
		}
	}
	if failedCount < 5 {
		t.Fatalf("expected at least 5 admin_auth_failed events, got %d", failedCount)
	}
	if lockoutCount < 1 {
		t.Fatalf("expected at least 1 admin_auth_lockout event, got %d", lockoutCount)
	}
}

func TestAdminSecurity_AuthLifecycleAndMutationAudits(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "")

	// Setup full set of admin dependencies
	tmpProtocols := t.TempDir()
	tmpAgents := t.TempDir()
	protoStore, err := protocol.NewFSStore(tmpProtocols)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	agentRepo := agent.NewFSRepository(tmpAgents)

	polStore, err := policy.OpenDuckDBStore(":memory:")
	if err != nil {
		t.Fatalf("OpenDuckDBStore: %v", err)
	}
	defer polStore.Close()
	if err := polStore.Migrate(context.Background()); err != nil {
		t.Fatalf("polStore.Migrate: %v", err)
	}
	if err := policy.Seed(context.Background(), polStore); err != nil {
		t.Fatalf("policy.Seed: %v", err)
	}
	compiler := policy.NewCompiler(polStore, policy.WithAgentsDir(tmpAgents))

	schemaStore, err := schema.OpenDuckDBSchemaStore(":memory:")
	if err != nil {
		t.Fatalf("OpenDuckDBSchemaStore: %v", err)
	}
	defer schemaStore.Close()
	if err := schemaStore.Migrate(context.Background()); err != nil {
		t.Fatalf("schemaStore.Migrate: %v", err)
	}
	_ = schemaStore.SaveSchema(context.Background(), &schema.ToolSchemaRecord{
		ToolName:    "demo_tool",
		ProtocolID:  "demo",
		SchemaJSON:  json.RawMessage(`{"type":"object"}`),
		SHA256Hash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	})

	guardDB, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(duckdb): %v", err)
	}
	defer guardDB.Close()
	guardCat := guard.NewCatalog(guardDB)
	if err := guardCat.Migrate(context.Background()); err != nil {
		t.Fatalf("guardCat.Migrate: %v", err)
	}
	if err := guardCat.Seed(context.Background()); err != nil {
		t.Fatalf("guardCat.Seed: %v", err)
	}
	settingsStore := settings.NewDuckDBStore(guardDB)
	if err := settingsStore.Migrate(context.Background()); err != nil {
		t.Fatalf("settingsStore.Migrate: %v", err)
	}

	ks := auth.NewMemoryKeyStore()
	adminRaw, adminRec, err := ks.GenerateKey("primary-admin", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Admin): %v", err)
	}
	devRaw, _, err := ks.GenerateKey("dev-key", "Developer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Developer): %v", err)
	}

	secSpy := &spySecurityAuditLogger{}
	toolSpy := &spyToolAuditLogger{}

	srv := NewAdminServer(AdminDependencies{
		Config: &config.Config{
			RuntimeMode:  config.RuntimeModeStandalone,
			AdminHost:    "0.0.0.0",
			AdminPort:    19415,
			ProtocolsDir: tmpProtocols,
			AgentsDir:    tmpAgents,
		},
		ReloadFunc:           func() error { return nil },
		SchemaClearFunc:      func() {},
		KeyStore:             ks,
		AgentRepo:            agentRepo,
		ProtocolStore:        protoStore,
		PolicyStore:          polStore,
		PolicyCompiler:       compiler,
		SchemaStore:          schemaStore,
		GuardCatalog:         guardCat,
		SettingsStore:        settingsStore,
		SettingsCache:        settings.NewCache(settings.DefaultOperationalSettings()),
		AuditLoggers:         []AuditEventLogger{toolSpy},
		SecurityAuditLoggers: []SecurityAuditEventLogger{secSpy},
	})
	h := srv.Handler()

	doJSON := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://127.0.0.1:19415"+target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminRaw)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Magic Link login + logout + Developer forbidden
	magicReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19415/admin/dashboard?token="+adminRaw, nil)
	magicRec := httptest.NewRecorder()
	h.ServeHTTP(magicRec, magicReq)
	if magicRec.Code != http.StatusSeeOther {
		t.Fatalf("magic link login = %d, want 303", magicRec.Code)
	}

	devReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19415/admin/status", nil)
	devReq.Header.Set("Authorization", "Bearer "+devRaw)
	devRec := httptest.NewRecorder()
	h.ServeHTTP(devRec, devReq)
	if devRec.Code != http.StatusForbidden {
		t.Fatalf("developer token = %d, want 403", devRec.Code)
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19415/admin/auth/logout", strings.NewReader(`{}`))
	logoutReq.Header.Set("Content-Type", "application/json")
	for _, c := range magicRec.Result().Cookies() {
		logoutReq.AddCookie(c)
	}
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", logoutRec.Code)
	}

	// 2. API Key Create + Revoke (ensure generated raw key is never leaked in SecurityAuditEvent)
	keyRec := doJSON(http.MethodPost, "/admin/api-keys", `{"name":"ci-bot","role":"Developer","agent_name":"alpha"}`)
	if keyRec.Code != http.StatusCreated {
		t.Fatalf("create api-key = %d: %s", keyRec.Code, keyRec.Body.String())
	}
	var createdKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	_ = json.Unmarshal(keyRec.Body.Bytes(), &createdKey)
	if delRec := doJSON(http.MethodDelete, "/admin/api-keys/"+createdKey.ID, ""); delRec.Code != http.StatusOK {
		t.Fatalf("revoke api-key = %d: %s", delRec.Code, delRec.Body.String())
	}

	// 3. Config Toggle + Clear Schemas + Schema Pin
	if rec := doJSON(http.MethodPost, "/admin/config/toggle", `{"filter_name":"dlp","enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("config toggle = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPost, "/admin/schemas/clear", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("schemas clear = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPost, "/admin/schemas/demo_tool/pin", `{"pinned":true}`); rec.Code != http.StatusOK {
		t.Fatalf("schema pin = %d: %s", rec.Code, rec.Body.String())
	}

	// 4. DLP Rule Create / Update / Delete
	if rec := doJSON(http.MethodPost, "/admin/dlp/rules", `{"id":"rule:sec-test","name":"Sec Test","description":"d","category":"custom","regex":"SECRET-[0-9]+","default_action":"mask"}`); rec.Code != http.StatusCreated {
		t.Fatalf("dlp create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPut, "/admin/dlp/rules/rule:sec-test", `{"name":"Sec Test 2","description":"d2","category":"custom","regex":"SECRET-[0-9]+","default_action":"block"}`); rec.Code != http.StatusOK {
		t.Fatalf("dlp update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodDelete, "/admin/dlp/rules/rule:sec-test", ""); rec.Code != http.StatusOK {
		t.Fatalf("dlp delete = %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Policy Pack Create / Update / Delete
	if rec := doJSON(http.MethodPost, "/admin/policy-packs", `{"id":"pack:sec-test","name":"Sec Pack","description":"d","category":"custom","rule_ids":["rule:kvkk-tc-kimlik"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("pack create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPut, "/admin/policy-packs/pack:sec-test", `{"name":"Sec Pack 2","description":"d2","category":"custom","rule_ids":["rule:kvkk-tc-kimlik"]}`); rec.Code != http.StatusOK {
		t.Fatalf("pack update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodDelete, "/admin/policy-packs/pack:sec-test", ""); rec.Code != http.StatusOK {
		t.Fatalf("pack delete = %d: %s", rec.Code, rec.Body.String())
	}

	// 6. Protocol Create / Update / Delete
	if rec := doJSON(http.MethodPost, "/admin/protocols", `{"id":"proto-sec","name":"Proto Sec","type":"http","url_or_command":"https://example.com/mcp"}`); rec.Code != http.StatusCreated {
		t.Fatalf("protocol create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPut, "/admin/protocols/proto-sec", `{"name":"Proto Sec Updated","type":"http","url_or_command":"https://example.com/mcp2"}`); rec.Code != http.StatusOK {
		t.Fatalf("protocol update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodDelete, "/admin/protocols/proto-sec", ""); rec.Code != http.StatusOK {
		t.Fatalf("protocol delete = %d: %s", rec.Code, rec.Body.String())
	}

	// 7. Agent Create / Update / DLP / Delete
	if rec := doJSON(http.MethodPost, "/admin/agents", `{"agent_name":"sec-agent","routing_mode":"aggregated","protocols":[{"id":"p1","name":"p1","type":"stdio","command":"echo"}]}`); rec.Code != http.StatusCreated {
		t.Fatalf("agent create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPut, "/admin/agents/sec-agent", `{"description":"updated"}`); rec.Code != http.StatusOK {
		t.Fatalf("agent update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPut, "/admin/agents/sec-agent/dlp", `{"pack_ids":[],"overrides":[],"custom_patterns":[],"tool_exemptions":{}}`); rec.Code != http.StatusOK {
		t.Fatalf("agent dlp update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodDelete, "/admin/agents/sec-agent", ""); rec.Code != http.StatusOK {
		t.Fatalf("agent delete = %d: %s", rec.Code, rec.Body.String())
	}

	// 8. Guard Policy Update & Global Deactivate
	models, err := guardCat.List(context.Background())
	if err != nil || len(models) == 0 {
		t.Fatalf("expected seeded guard models, got %v (%d)", err, len(models))
	}
	if rec := doJSON(http.MethodPut, "/admin/guards/models/"+models[0].ID+"/policy", `{"default_action":"BLOCK","critical_tools":["rm_rf"]}`); rec.Code != http.StatusOK {
		t.Fatalf("guard policy = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(http.MethodPost, "/admin/guards/models/deactivate", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("guard deactivate global = %d: %s", rec.Code, rec.Body.String())
	}

	// Assert ZERO events in tool_audit_logs, and all expected control-plane events present with NO secret leaks
	if got := len(toolSpy.Events()); got != 0 {
		t.Fatalf("expected 0 tool_audit_logs for control-plane mutations, got %d", got)
	}

	events := secSpy.Events()
	wantTypes := map[string]bool{
		"admin_auth_success":   false,
		"admin_auth_forbidden": false,
		"admin_auth_logout":    false,
		"api_key_created":      false,
		"api_key_revoked":      false,
		"config_mutated":       false,
		"schemas_cleared":      false,
		"schema_pinned":        false,
		"dlp_rule_mutated":     false,
		"policy_pack_mutated":  false,
		"protocol_mutated":     false,
		"agent_mutated":        false,
		"agent_dlp_updated":    false,
		"guard_policy_updated": false,
		"guard_mutated":        false,
	}

	for _, ev := range events {
		if _, ok := wantTypes[ev.EventType]; ok {
			wantTypes[ev.EventType] = true
		}
		if ev.EventType == "admin_auth_success" && ev.ActorID != adminRec.ID {
			t.Errorf("admin_auth_success ActorID = %q, want %q", ev.ActorID, adminRec.ID)
		}
		blob, _ := json.Marshal(ev)
		s := string(blob)
		if strings.Contains(s, adminRaw) || strings.Contains(s, devRaw) || (createdKey.RawKey != "" && strings.Contains(s, createdKey.RawKey)) || strings.Contains(s, "?token=") {
			t.Fatalf("security audit event leaked token/query: %s", s)
		}
	}

	for eventType, seen := range wantTypes {
		if !seen {
			t.Errorf("missing expected SecurityAuditEvent type %q", eventType)
		}
	}
}

func TestWSHub_CapturesVerifiedActorAndClientIP(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "")

	ks, err := auth.NewFileKeyStore(filepath.Join(t.TempDir(), "keys", "api_keys.json"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	adminRaw, adminRec, err := ks.GenerateKey("ws-admin", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	srv := NewAdminServer(AdminDependencies{
		Config: &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
			AdminHost:   "0.0.0.0",
			AdminPort:   19415,
		},
		KeyStore: ks,
	})
	h := srv.Handler()

	// Obtain session cookie
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19415/admin/auth/session", strings.NewReader(`{"token":"`+adminRaw+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == adminSessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}

	ts := newTestServer(t, h)
	if ts == nil {
		return
	}
	defer ts.Close()

	addr := strings.TrimPrefix(ts.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}
	defer conn.Close()

	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Origin: http://" + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Cookie: " + sessionCookie.Name + "=" + sessionCookie.Value + "\r\n" +
		"X-User-ID: spoofed-ws-actor\r\n\r\n"
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS status = %d, want 101", resp.StatusCode)
	}

	deadline := time.Now().Add(time.Second)
	var client *wsClient
	for time.Now().Before(deadline) {
		srv.wsHub.mu.RLock()
		for c := range srv.wsHub.clients {
			client = c
			break
		}
		srv.wsHub.mu.RUnlock()
		if client != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if client == nil {
		t.Fatal("expected registered wsClient in WSHub")
	}
	if client.actorID != adminRec.ID {
		t.Fatalf("wsClient.actorID = %q, want %q", client.actorID, adminRec.ID)
	}
	if client.clientIP == "" {
		t.Fatal("expected non-empty wsClient.clientIP")
	}
}
