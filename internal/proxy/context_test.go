package proxy

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
)

func TestContextExtractor_Authenticate_FailClosedCases(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	devToken, devRec, err := keyStore.GenerateKey("Cursor Dev Agent", "Developer", "cursor-profile")
	if err != nil {
		t.Fatalf("GenerateKey(Developer): %v", err)
	}
	namelessToken, namelessRec, err := keyStore.GenerateKey(" ", "Agent", "*")
	if err == nil && namelessRec != nil {
		_ = namelessToken
	}
	adminToken, _, err := keyStore.GenerateKey("Admin Key", auth.DefaultAdminRole, "*")
	if err != nil {
		t.Fatalf("GenerateKey(Admin): %v", err)
	}
	revokedToken, revokedRec, err := keyStore.GenerateKey("Revoked Key", "Developer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Revoked): %v", err)
	}
	if err := keyStore.RevokeKey(revokedRec.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	tests := []struct {
		name      string
		extractor *ContextExtractor
		setupReq  func() *httptest.ResponseRecorder
		buildReq  func() (string, string, map[string]string)
		wantErr   error
		wantRole  string
		wantUser  string
		wantKeyID string
		wantAgent string
	}{
		{
			name:      "nil keyValidator fails closed even on loopback",
			extractor: NewContextExtractor(),
			buildReq: func() (string, string, map[string]string) {
				return "127.0.0.1:43210", "", map[string]string{
					"Authorization": "Bearer " + devToken,
					"X-User-ID":     "spoofed",
					"X-User-Role":   "Admin",
				}
			},
			wantErr: ErrUnauthorized,
		},
		{
			name:      "missing Authorization fails closed even from loopback or RFC1918",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "10.0.0.5:43210", "", map[string]string{
					"X-User-ID":               "alice",
					"X-User-Role":             "Admin",
					"X-FaradAiWire-Signature": "t=1700000000,v1=deadbeef",
				}
			},
			wantErr: ErrUnauthorized,
		},
		{
			name:      "X-API-Key header alone is rejected",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "127.0.0.1:43210", "", map[string]string{
					"X-API-Key": devToken,
				}
			},
			wantErr: ErrUnauthorized,
		},
		{
			name:      "invalid Bearer token is rejected",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "127.0.0.1:43210", "", map[string]string{
					"Authorization": "Bearer faw_live_invalid_secret",
				}
			},
			wantErr: ErrUnauthorized,
		},
		{
			name:      "revoked Bearer token is rejected",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "127.0.0.1:43210", "", map[string]string{
					"Authorization": "Bearer " + revokedToken,
				}
			},
			wantErr: ErrUnauthorized,
		},
		{
			name:      "admin Bearer token is rejected with ErrForbiddenAdminKeyOnIngress",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "127.0.0.1:43210", "", map[string]string{
					"Authorization": "Bearer " + adminToken,
				}
			},
			wantErr: ErrForbiddenAdminKeyOnIngress,
		},
		{
			name:      "valid Bearer token ignores spoofed X-User-ID and X-User-Role headers",
			extractor: NewContextExtractor(keyStore),
			buildReq: func() (string, string, map[string]string) {
				return "198.51.100.25:55555", "", map[string]string{
					"Authorization": "bearer " + devToken,
					"X-User-ID":     "spoofed-user",
					"X-User-Role":   "Admin",
				}
			},
			wantRole:  "Developer",
			wantUser:  "Cursor Dev Agent",
			wantKeyID: devRec.ID,
			wantAgent: "cursor-profile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			remoteAddr, _, hdrs := tc.buildReq()
			req := httptest.NewRequest("POST", "/message", nil)
			req.RemoteAddr = remoteAddr
			for k, v := range hdrs {
				req.Header.Set(k, v)
			}

			uCtx, authErr := tc.extractor.Authenticate(req)
			if tc.wantErr != nil {
				if !errors.Is(authErr, tc.wantErr) {
					t.Fatalf("Authenticate() error = %v, want %v", authErr, tc.wantErr)
				}
				if uCtx != nil {
					t.Fatalf("expected nil UserContext on error, got %+v", uCtx)
				}
				if tc.extractor.Extract(req) != nil {
					t.Fatalf("expected Extract() nil on error")
				}
				return
			}

			if authErr != nil {
				t.Fatalf("unexpected Authenticate() error: %v", authErr)
			}
			if uCtx == nil {
				t.Fatalf("expected non-nil UserContext")
			}
			if uCtx.Role != tc.wantRole {
				t.Errorf("Role = %q, want %q", uCtx.Role, tc.wantRole)
			}
			if uCtx.UserID != tc.wantUser {
				t.Errorf("UserID = %q, want %q", uCtx.UserID, tc.wantUser)
			}
			if uCtx.APIKeyID != tc.wantKeyID {
				t.Errorf("APIKeyID = %q, want %q", uCtx.APIKeyID, tc.wantKeyID)
			}
			if uCtx.AgentName != tc.wantAgent {
				t.Errorf("AgentName = %q, want %q", uCtx.AgentName, tc.wantAgent)
			}
			if uCtx.ClientIP != "198.51.100.25" {
				t.Errorf("ClientIP = %q, want 198.51.100.25", uCtx.ClientIP)
			}
		})
	}

	if uCtx, nilErr := NewContextExtractor(keyStore).Authenticate(nil); !errors.Is(nilErr, ErrUnauthorized) || uCtx != nil {
		t.Fatalf("Authenticate(nil) = (%+v, %v), want (nil, ErrUnauthorized)", uCtx, nilErr)
	}
}

func BenchmarkContextExtractor_Extract_Bearer(b *testing.B) {
	keyStore := auth.NewMemoryKeyStore()
	rawToken, _, err := keyStore.GenerateKey("Bench Key", "Developer", "*")
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	extractor := NewContextExtractor(keyStore)

	req := httptest.NewRequest("POST", "/message", nil)
	req.RemoteAddr = "127.0.0.1:45678"
	req.Header.Set("Authorization", "Bearer "+rawToken)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(req)
	}
}
