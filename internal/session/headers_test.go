package session

import (
	"net/http"
	"testing"
)

func TestSanitizeUpstreamHeaders(t *testing.T) {
	inbound := make(http.Header)
	inbound.Set("Authorization", "Bearer faw_live_client_secret_token_12345")
	inbound.Set("X-API-Key", "faw_live_api_key_67890")
	inbound.Set("Cookie", "session=super-secret-user-cookie")
	inbound.Set("X-FaradAiWire-Signature", "t=1700000000,v1=abcdef")
	inbound.Set("X-FaradAiWire-Timestamp", "1700000000")
	inbound.Set("X-FaradAiWire-User-Role", "Admin")
	inbound.Set("Connection", "keep-alive")
	inbound.Set("Upgrade", "websocket")
	inbound.Set("Accept-Encoding", "gzip, deflate")
	inbound.Set("Content-Type", "application/json")
	inbound.Set("X-Request-ID", "req-1234")
	inbound.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	t.Run("strips_client_credentials_and_injects_upstream_token", func(t *testing.T) {
		sanitized := SanitizeUpstreamHeaders(inbound, "upstream-mcp-token-xyz")

		// Must strip client sensitive ingress headers
		if sanitized.Get("X-API-Key") != "" {
			t.Errorf("expected X-API-Key to be stripped, got %q", sanitized.Get("X-API-Key"))
		}
		if sanitized.Get("Cookie") != "" {
			t.Errorf("expected Cookie to be stripped, got %q", sanitized.Get("Cookie"))
		}
		if sanitized.Get("X-FaradAiWire-Signature") != "" {
			t.Errorf("expected X-FaradAiWire-Signature to be stripped")
		}
		if sanitized.Get("X-FaradAiWire-Timestamp") != "" {
			t.Errorf("expected X-FaradAiWire-Timestamp to be stripped")
		}
		if sanitized.Get("X-FaradAiWire-User-Role") != "" {
			t.Errorf("expected X-FaradAiWire-User-Role to be stripped")
		}
		if sanitized.Get("Connection") != "" {
			t.Errorf("expected Connection hop-by-hop header to be stripped")
		}

		// Must preserve safe headers
		if sanitized.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json preserved, got %q", sanitized.Get("Content-Type"))
		}
		if sanitized.Get("X-Request-ID") != "req-1234" {
			t.Errorf("expected X-Request-ID req-1234 preserved, got %q", sanitized.Get("X-Request-ID"))
		}
		if sanitized.Get("Traceparent") == "" {
			t.Errorf("expected Traceparent header preserved")
		}

		// Must inject upstream token, NOT the client token
		if sanitized.Get("Authorization") != "Bearer upstream-mcp-token-xyz" {
			t.Errorf("expected Authorization Bearer upstream-mcp-token-xyz, got %q", sanitized.Get("Authorization"))
		}
	})

	t.Run("strips_client_credentials_without_upstream_token", func(t *testing.T) {
		sanitized := SanitizeUpstreamHeaders(inbound, "")

		// When no upstream token is configured, Authorization must be completely empty!
		if sanitized.Get("Authorization") != "" {
			t.Errorf("expected Authorization to be empty when upstream token is empty, got %q", sanitized.Get("Authorization"))
		}
		if sanitized.Get("X-API-Key") != "" {
			t.Errorf("expected X-API-Key to be stripped")
		}
		if sanitized.Get("Cookie") != "" {
			t.Errorf("expected Cookie to be stripped")
		}
	})

	t.Run("handles_nil_headers_safely", func(t *testing.T) {
		sanitized := SanitizeUpstreamHeaders(nil, "token-abc")
		if sanitized.Get("Authorization") != "Bearer token-abc" {
			t.Errorf("expected Authorization Bearer token-abc, got %q", sanitized.Get("Authorization"))
		}
	})

	t.Run("injects_custom_headers_safely", func(t *testing.T) {
		custom := map[string]string{
			"Context7-API-Key": "ctx7_live_secret_abc123",
			"X-API-Key":        "upstream-configured-key",
			"X-Tenant-ID":      "tenant-42",
			"Connection":       "close", // hop-by-hop, must be ignored
		}
		sanitized := SanitizeUpstreamHeadersWithCustom(inbound, "upstream-token-123", custom)

		// Must strip client's ingress X-API-Key and inject protocol's configured X-API-Key
		if sanitized.Get("X-API-Key") != "upstream-configured-key" {
			t.Errorf("expected X-API-Key to be upstream-configured-key, got %q", sanitized.Get("X-API-Key"))
		}
		// Must inject custom headers
		if sanitized.Get("Context7-API-Key") != "ctx7_live_secret_abc123" {
			t.Errorf("expected Context7-API-Key, got %q", sanitized.Get("Context7-API-Key"))
		}
		if sanitized.Get("X-Tenant-ID") != "tenant-42" {
			t.Errorf("expected X-Tenant-ID tenant-42, got %q", sanitized.Get("X-Tenant-ID"))
		}
		// Blocked hop-by-hop must not be injected
		if sanitized.Get("Connection") != "" {
			t.Errorf("expected Connection header to remain blocked")
		}
	})
}
