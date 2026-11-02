package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

func TestGateway_DuckDBTelemetry_Integration(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_gateway_telemetry.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  8080,
		AdminPort:   8095,
		Telemetry: config.TelemetryConfig{
			DBPath:          dbPath,
			RetentionDays:   14,
			MaxSizeBytes:    10 * 1024 * 1024,
			MaxPayloadBytes: 64 * 1024,
			BufferSize:      1000,
			BatchFlushMs:    20,
		},
	}

	srv, err := gateway.NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	defer srv.Shutdown(context.Background())

	telemetryEngine := srv.TelemetryEngine()
	if telemetryEngine == nil {
		t.Fatalf("expected telemetryEngine to be initialized, got nil")
	}

	// 1. Send normal tool call through pipeline
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "agent-coder")
	ctx = context.WithValue(ctx, types.UserContextKey, &types.UserContext{UserID: "usr-42", Role: "admin"})

	req1 := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"fetch_code","arguments":{"repo":"farad-ai"}}`),
		ID:      "call-1",
	}

	_, mcpErr := srv.Pipeline().ProcessRequest(ctx, req1)
	if mcpErr != nil {
		t.Fatalf("unexpected filter error: %v", mcpErr)
	}

	resp1 := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"func main() {}"}]}`),
		ID:      "call-1",
	}

	ctxResp := context.WithValue(ctx, types.ToolNameContextKey, "fetch_code")
	_, mcpErr2 := srv.Pipeline().ProcessResponse(ctxResp, resp1)
	if mcpErr2 != nil {
		t.Fatalf("unexpected filter response error: %v", mcpErr2)
	}

	// 2. Send large payload (> 64 KB) to verify truncation in DuckDB
	largeContent := strings.Repeat("X", 80*1024) // 80 KB
	largePayload := fmt.Sprintf(`{"name":"dump_logs","arguments":{"data":"%s"}}`, largeContent)
	reqLarge := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(largePayload),
		ID:      "call-large",
	}

	_, _ = srv.Pipeline().ProcessRequest(ctx, reqLarge)

	// Wait for write-behind flush
	time.Sleep(150 * time.Millisecond)

	// 3. Query via /admin/audit-logs
	adminHandler := srv.AdminHandler()
	httpReq := httptest.NewRequest("GET", "/admin/audit-logs?limit=50", nil)
	httpRec := httptest.NewRecorder()

	adminHandler.ServeHTTP(httpRec, httpReq)

	if httpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/audit-logs, got %d: %s", httpRec.Code, httpRec.Body.String())
	}

	var respBody struct {
		Enabled bool                 `json:"enabled"`
		Total   int64                `json:"total"`
		Limit   int                  `json:"limit"`
		Offset  int                  `json:"offset"`
		Logs    []duckdb.AuditRecord `json:"logs"`
	}

	if err := json.Unmarshal(httpRec.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("failed to parse /admin/audit-logs response: %v", err)
	}

	if !respBody.Enabled {
		t.Errorf("expected audit logs enabled = true")
	}

	if respBody.Total < 2 {
		t.Fatalf("expected at least 2 logged events in DuckDB, got %d", respBody.Total)
	}

	// Verify the fetch_code call
	var foundNormal, foundLarge bool
	for _, l := range respBody.Logs {
		if l.ToolName == "fetch_code" {
			foundNormal = true
			if l.AgentName != "agent-coder" {
				t.Errorf("expected agent-coder, got %s", l.AgentName)
			}
			if l.CallerRole != "admin" {
				t.Errorf("expected caller_role admin, got %s", l.CallerRole)
			}
			if l.Decision != "ALLOWED" {
				t.Errorf("expected ALLOWED decision, got %s", l.Decision)
			}
			if l.IntegrityHash == "" {
				t.Errorf("expected non-empty integrity hash")
			}
		}

		if l.ToolName == "dump_logs" {
			foundLarge = true
			if !strings.Contains(l.RawPayloadPreview, "[TRUNCATED - Total Size: 80.0") {
				t.Errorf("expected payload preview to contain truncation trailer, got: %s", l.RawPayloadPreview[len(l.RawPayloadPreview)-100:])
			}
			if len(l.RawPayloadPreview) > 65*1024 {
				t.Errorf("preview exceeded expected bounded size: %d", len(l.RawPayloadPreview))
			}
		}
	}

	if !foundNormal {
		t.Errorf("fetch_code call not found in DuckDB audit logs")
	}
	if !foundLarge {
		t.Errorf("dump_logs large payload call not found in DuckDB audit logs")
	}
}
