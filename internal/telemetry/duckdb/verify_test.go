package duckdb

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestV2CanonicalHash_RejectsDelimiterCollisionAndSupportsHMAC(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Microsecond)

	// Adjacent field boundary shift: ("ab|c", "d") vs ("ab", "c|d")
	hA, verA := ComputeToolLogHashV2(nil, "id-1", ts, "", "ab|c", "dev", "d", "role", "", "", "", "", "ALLOWED", "", 0, "", 1.0, "", "", "", "", "", false, "", "")
	hB, _ := ComputeToolLogHashV2(nil, "id-1", ts, "", "ab", "dev", "c|d", "role", "", "", "", "", "ALLOWED", "", 0, "", 1.0, "", "", "", "", "", false, "", "")
	if hA == hB {
		t.Fatalf("delimiter collision detected between distinct field tuples: %q", hA)
	}
	if verA != "v2" || !strings.HasPrefix(hA, "v2:sha256:") {
		t.Fatalf("expected v2:sha256 digest and v2 hash_version, got ver=%q hash=%q", verA, hA)
	}

	hmacKey := []byte("super-secret-hmac-key")
	hHMAC, verHMAC := ComputeToolLogHashV2(hmacKey, "id-1", ts, "", "ab|c", "dev", "d", "role", "", "", "", "", "ALLOWED", "", 0, "", 1.0, "", "", "", "", "", false, "", "")
	if verHMAC != "v2-hmac" || !strings.HasPrefix(hHMAC, "v2:hmac-sha256:") {
		t.Fatalf("expected v2:hmac-sha256 digest and v2-hmac hash_version, got ver=%q hash=%q", verHMAC, hHMAC)
	}
}

func TestVerifyIntegrity_DetectsTamperingAcrossAllTablesAndDisablesReadRecompute(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "verify.duckdb")
	eng, err := New(Config{
		DBPath:       dbPath,
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New: %v", err)
	}
	defer eng.Close()

	// 1. Insert paired request + response in tool_audit_logs/tool_audit_responses, plus a security_audit_logs row
	eng.LogEvent(&filter.AuditEvent{
		ID:              "inv-v2-1",
		TraceID:         "tr-v2-1",
		Timestamp:       time.Now().UTC(),
		AgentName:       "alpha",
		ToolName:        "exec_cmd",
		CallerRole:      "Developer",
		Phase:           filter.AuditPhaseRequest,
		Decision:        filter.DecisionAllowed,
		RequestDecision: filter.DecisionAllowed,
		HumanApproved:   true,
		ApprovedBy:      "key_op_1",
		ApprovalChannel: "web_rest",
		OriginalRequest: `{"cmd":"ls"}`,
		Request:         `{"cmd":"ls"}`,
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:               "inv-v2-1",
		TraceID:          "tr-v2-1",
		Timestamp:        time.Now().UTC(),
		AgentName:        "alpha",
		ToolName:         "exec_cmd",
		CallerRole:       "Developer",
		Phase:            filter.AuditPhaseResponse,
		Decision:         filter.DecisionMasked,
		ResponseDecision: filter.DecisionMasked,
		OriginalResponse: `{"secret":"sk-123"}`,
		Response:         `{"secret":"[REDACTED]"}`,
	})
	eng.LogSecurityEvent(&filter.SecurityAuditEvent{
		ID:           "sec-v2-1",
		Timestamp:    time.Now().UTC(),
		EventType:    "admin_auth_success",
		ActorID:      "key_op_1",
		ActorRole:    "admin",
		ClientIP:     "127.0.0.1",
		ResourceType: "admin_auth",
		ResourceID:   "/admin/auth/session",
		Action:       "session_api",
		Outcome:      "allowed",
	})

	if err := eng.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Insert one authentic legacy v1 row directly to ensure legacy_v1 distinction works
	legacyTS := time.Now().UTC().Truncate(time.Microsecond)
	v1Hash := ComputeIntegrityHash("inv-legacy-v1", legacyTS, "alpha", "ping", "Developer", "ALLOWED", 1.2, "ok")
	if _, err := eng.DB().Exec(`
		INSERT INTO tool_audit_logs (
			id, timestamp, agent_name, release_version, tool_name, caller_role, decision, latency_ms, raw_payload_preview, hash_version, integrity_hash
		) VALUES (?, ?, ?, '0.1.5', ?, ?, ?, ?, ?, 'v1', ?)
	`, "inv-legacy-v1", legacyTS, "alpha", "ping", "Developer", "ALLOWED", 1.2, "ok", v1Hash); err != nil {
		t.Fatalf("insert v1 row: %v", err)
	}

	// Initial verification must succeed
	report, err := eng.VerifyIntegrity(context.Background(), nil)
	if err != nil {
		t.Fatalf("VerifyIntegrity initial: %v", err)
	}
	if !report.Valid {
		t.Fatalf("expected valid initial report, got %+v", report)
	}
	if report.ToolAuditLogs.V2Verified != 1 || report.ToolAuditLogs.LegacyV1 != 1 {
		t.Fatalf("unexpected ToolAuditLogs counts: %+v", report.ToolAuditLogs)
	}
	if report.ToolAuditResponses.V2Verified != 1 || report.SecurityAuditLogs.V2Verified != 1 {
		t.Fatalf("unexpected response/security verified counts: resp=%+v sec=%+v", report.ToolAuditResponses, report.SecurityAuditLogs)
	}

	// Capture stored hash on read before tampering
	beforeRec, err := eng.GetAuditLogByID(context.Background(), "inv-v2-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID before: %v", err)
	}
	if !strings.HasPrefix(beforeRec.IntegrityHash, "v2:sha256:") {
		t.Fatalf("expected persisted v2:sha256 hash on read, got %q", beforeRec.IntegrityHash)
	}

	// Mutate rows in all three tables WITHOUT updating integrity_hash (use temp copy + reinsert so ART secondary indexes never block SQL tamper test)
	if _, err := eng.DB().Exec(`
		CREATE TEMP TABLE _t_tool AS SELECT * FROM tool_audit_logs WHERE id = 'inv-v2-1';
		UPDATE _t_tool SET decision = 'BLOCKED';
		DELETE FROM tool_audit_logs WHERE id = 'inv-v2-1';
		INSERT INTO tool_audit_logs SELECT * FROM _t_tool;
		DROP TABLE _t_tool;
	`); err != nil {
		t.Fatalf("tamper tool_audit_logs: %v", err)
	}
	if _, err := eng.DB().Exec(`UPDATE tool_audit_responses SET response_decision = 'ALLOWED' WHERE invocation_id = 'inv-v2-1'`); err != nil {
		t.Fatalf("tamper tool_audit_responses: %v", err)
	}
	if _, err := eng.DB().Exec(`
		CREATE TEMP TABLE _t_sec AS SELECT * FROM security_audit_logs WHERE id = 'sec-v2-1';
		UPDATE _t_sec SET outcome = 'denied';
		DELETE FROM security_audit_logs WHERE id = 'sec-v2-1';
		INSERT INTO security_audit_logs SELECT * FROM _t_sec;
		DROP TABLE _t_sec;
	`); err != nil {
		t.Fatalf("tamper security_audit_logs: %v", err)
	}

	// QueryAuditLogs and GetAuditLogByID MUST NOT recompute IntegrityHash on read!
	afterRec, err := eng.GetAuditLogByID(context.Background(), "inv-v2-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID after tamper: %v", err)
	}
	if afterRec.IntegrityHash != beforeRec.IntegrityHash {
		t.Fatalf("GetAuditLogByID silently recomputed IntegrityHash on read! before=%q after=%q", beforeRec.IntegrityHash, afterRec.IntegrityHash)
	}
	listRes, err := eng.QueryAuditLogs(context.Background(), QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("QueryAuditLogs after tamper: %v", err)
	}
	for _, item := range listRes.Logs {
		if item.ID == "inv-v2-1" && item.IntegrityHash != beforeRec.IntegrityHash {
			t.Fatalf("QueryAuditLogs silently recomputed IntegrityHash on read! before=%q after=%q", beforeRec.IntegrityHash, item.IntegrityHash)
		}
	}

	// VerifyIntegrity MUST detect tampering across all 3 tables
	tampered, err := eng.VerifyIntegrity(context.Background(), nil)
	if err != nil {
		t.Fatalf("VerifyIntegrity tampered: %v", err)
	}
	if tampered.Valid {
		t.Fatal("expected VerifyIntegrity Valid=false after SQL tampering")
	}
	if len(tampered.ToolAuditLogs.TamperedIDs) == 0 || tampered.ToolAuditLogs.TamperedIDs[0] != "inv-v2-1" {
		t.Errorf("expected inv-v2-1 in ToolAuditLogs.TamperedIDs, got %+v", tampered.ToolAuditLogs.TamperedIDs)
	}
	if len(tampered.ToolAuditResponses.TamperedIDs) == 0 {
		t.Errorf("expected tampered response row ID in ToolAuditResponses.TamperedIDs")
	}
	if len(tampered.SecurityAuditLogs.TamperedIDs) == 0 || tampered.SecurityAuditLogs.TamperedIDs[0] != "sec-v2-1" {
		t.Errorf("expected sec-v2-1 in SecurityAuditLogs.TamperedIDs, got %+v", tampered.SecurityAuditLogs.TamperedIDs)
	}
}

func TestVerifyIntegrity_HMACKeyVerification(t *testing.T) {
	t.Setenv("FARADAI_WIRE_AUDIT_HMAC_KEY", "test-audit-hmac-secret-v2")

	dbPath := filepath.Join(t.TempDir(), "verify_hmac.duckdb")
	eng, err := New(Config{DBPath: dbPath, BufferSize: 50, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("duckdb.New: %v", err)
	}
	defer eng.Close()

	eng.LogEvent(&filter.AuditEvent{
		ID:        "inv-hmac-1",
		Timestamp: time.Now().UTC(),
		AgentName: "alpha",
		ToolName:  "read",
		Decision:  filter.DecisionAllowed,
	})
	if err := eng.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Correct key succeeds
	okRep, err := eng.VerifyIntegrity(context.Background(), []byte("test-audit-hmac-secret-v2"))
	if err != nil || !okRep.Valid || !okRep.HMACEnabled {
		t.Fatalf("expected valid HMAC report, got rep=%+v err=%v", okRep, err)
	}

	// Wrong key fails
	badRep, err := eng.VerifyIntegrity(context.Background(), []byte("wrong-key"))
	if err != nil || badRep.Valid || len(badRep.ToolAuditLogs.TamperedIDs) == 0 {
		t.Fatalf("expected mismatched HMAC key failure, got rep=%+v err=%v", badRep, err)
	}
}
