package duckdb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
)

func TestEngine_AdditiveMigration_PreservesLegacyRowsAndAddsAttributionCols(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_arch050.duckdb")

	rawDB, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open raw db failed: %v", err)
	}
	_, err = rawDB.Exec(`
		CREATE TABLE tool_audit_logs (
			id VARCHAR PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			trace_id VARCHAR,
			agent_name VARCHAR NOT NULL,
			release_version VARCHAR NOT NULL,
			tool_name VARCHAR NOT NULL,
			caller_role VARCHAR DEFAULT 'default',
			decision VARCHAR NOT NULL,
			request_decision VARCHAR,
			response_decision VARCHAR,
			matched_rule VARCHAR,
			error_message TEXT,
			latency_ms DOUBLE NOT NULL,
			input_size_bytes INTEGER,
			output_size_bytes INTEGER,
			raw_payload_preview TEXT,
			original_payload_preview TEXT,
			original_request TEXT,
			request TEXT,
			original_response TEXT,
			response TEXT,
			integrity_hash VARCHAR NOT NULL
		);
		INSERT INTO tool_audit_logs (
			id, trace_id, agent_name, release_version, tool_name, caller_role,
			decision, latency_ms, integrity_hash
		) VALUES (
			'legacy-row-1', 'legacy-trace-1', 'agent-legacy', '0.1.6', 'read_file',
			'Developer', 'ALLOWED', 2.5, 'legacy-sha-hex'
		);
	`)
	if err != nil {
		_ = rawDB.Close()
		t.Fatalf("seed legacy db failed: %v", err)
	}
	_ = rawDB.Close()

	engine, err := New(Config{DBPath: dbPath, BufferSize: 100, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("New engine on legacy schema failed: %v", err)
	}
	defer engine.Close()

	// Insert new invocation with full attribution + HITL provenance
	engine.LogEvent(&filter.AuditEvent{
		ID:              "inv-attr-1",
		TraceID:         "trace-attr-1",
		Timestamp:       time.Now().UTC(),
		AgentName:       "agent-prod",
		Method:          "tools/call",
		ToolName:        "delete_record",
		PathType:        "DEEP_PATH",
		FilterName:      "hitl",
		Decision:        filter.DecisionAllowed,
		RequestDecision: filter.DecisionAllowed,
		ErrorCode:       0,
		LatencyMs:       12.4,
		APIKeyID:        "key-dev-42",
		ClientIP:        "172.18.0.5",
		HumanApproved:   true,
		ApprovedBy:      "key-admin-1",
		ApprovalChannel: "web_ws",
		AuditedRules:    []string{"audit_rule_1", "audit_rule_2"},
		User: &types.UserContext{
			UserID:   "alice",
			Role:     "Developer",
			APIKeyID: "key-dev-42",
			ClientIP: "172.18.0.5",
		},
	})
	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	ctx := context.Background()
	legacy, err := engine.GetAuditLogByID(ctx, "legacy-row-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID legacy failed: %v", err)
	}
	if legacy.HashVersion != "v1" {
		t.Fatalf("expected migrated legacy row hash_version='v1', got %q", legacy.HashVersion)
	}

	rec, err := engine.GetAuditLogByID(ctx, "inv-attr-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID inv-attr-1 failed: %v", err)
	}
	if rec.UserID != "alice" {
		t.Errorf("expected UserID='alice', got %q", rec.UserID)
	}
	if rec.UserContext["user_id"] != "alice" {
		t.Errorf("expected UserContext[user_id]='alice' (not agent_name), got %v", rec.UserContext["user_id"])
	}
	if rec.APIKeyID != "key-dev-42" {
		t.Errorf("expected APIKeyID='key-dev-42', got %q", rec.APIKeyID)
	}
	if rec.ClientIP != "172.18.0.5" {
		t.Errorf("expected ClientIP='172.18.0.5', got %q", rec.ClientIP)
	}
	if rec.PathType != "DEEP_PATH" {
		t.Errorf("expected PathType='DEEP_PATH', got %q", rec.PathType)
	}
	if !rec.HumanApproved || rec.ApprovedBy != "key-admin-1" || rec.ApprovalChannel != "web_ws" {
		t.Errorf("unexpected HITL provenance: approved=%v by=%q chan=%q", rec.HumanApproved, rec.ApprovedBy, rec.ApprovalChannel)
	}
	if len(rec.AuditedRules) != 2 || rec.AuditedRules[0] != "audit_rule_1" {
		t.Errorf("expected 2 audited rules, got %v", rec.AuditedRules)
	}
}

func TestEngine_SecurityAuditLogs_IsolationAndRetention(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "security_audit.duckdb")

	engine, err := New(Config{
		DBPath:        dbPath,
		RetentionDays: 14,
		BufferSize:    100,
		BatchFlushMs:  10,
	})
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	defer engine.Close()

	now := time.Now().UTC()
	engine.LogSecurityEvent(&filter.SecurityAuditEvent{
		ID:        "sec-old",
		Timestamp: now.AddDate(0, 0, -30),
		EventType: "ADMIN_LOGIN_FAILED",
		ActorID:   "unknown",
		ActorRole: "anonymous",
		ClientIP:  "10.0.0.2",
		Action:    "LOGIN",
		Outcome:   "DENIED",
		Reason:    "INVALID_CREDENTIALS",
	})
	engine.LogSecurityEvent(&filter.SecurityAuditEvent{
		ID:           "sec-new",
		Timestamp:    now,
		TraceID:      "tr-sec-99",
		EventType:    "API_KEY_CREATE",
		ActorID:      "key-admin-1",
		ActorRole:    "Admin",
		ClientIP:     "127.0.0.1",
		ResourceType: "api_key",
		ResourceID:   "key-dev-7",
		Action:       "CREATE",
		Outcome:      "ALLOWED",
		Metadata:     map[string]any{"agent_name": "cursor"},
	})

	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	ctx := context.Background()

	// Must NOT pollute tool_audit_logs
	toolRes, err := engine.QueryAuditLogs(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAuditLogs failed: %v", err)
	}
	if toolRes.Total != 0 {
		t.Fatalf("expected 0 tool_audit_logs rows, got %d", toolRes.Total)
	}

	// Retention sweep prunes sec-old, preserves sec-new
	if err := engine.RetentionCleaner().EnforceRetention(ctx); err != nil {
		t.Fatalf("EnforceRetention failed: %v", err)
	}

	secRes, err := engine.QuerySecurityAuditLogs(ctx, SecurityQueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QuerySecurityAuditLogs failed: %v", err)
	}
	if secRes.Total != 1 || len(secRes.Events) != 1 {
		t.Fatalf("expected 1 retained security audit event, got total=%d len=%d", secRes.Total, len(secRes.Events))
	}
	got := secRes.Events[0]
	if got.ID != "sec-new" || got.ActorID != "key-admin-1" || got.EventType != "API_KEY_CREATE" {
		t.Fatalf("unexpected security audit record: %+v", got)
	}
	if got.IntegrityHash == "" {
		t.Fatal("expected non-empty IntegrityHash on security_audit_logs row")
	}
}
