package duckdb

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrDatabaseLocked indicates the target DuckDB file is currently locked by another process (e.g. running daemon).
var ErrDatabaseLocked = errors.New("telemetry DuckDB file is locked by another process; query GET /admin/audit/verify or pass --jsonl")

const maxReportedTamperedIDs = 200

// TableIntegrityReport summarizes integrity verification counts and tampered row IDs for one DuckDB table.
type TableIntegrityReport struct {
	Checked       int      `json:"checked"`
	V2Verified    int      `json:"v2_verified"`
	LegacyV1      int      `json:"legacy_v1"`
	TamperedCount int      `json:"tampered_count,omitempty"`
	TamperedIDs   []string `json:"tampered_ids"`
}

func (r *TableIntegrityReport) recordTampered(id string) {
	r.TamperedCount++
	if len(r.TamperedIDs) < maxReportedTamperedIDs {
		r.TamperedIDs = append(r.TamperedIDs, id)
	}
}

// IntegrityReport aggregates cryptographic tamper-evidence verification across all DuckDB audit tables.
type IntegrityReport struct {
	Valid              bool                 `json:"valid"`
	HMACEnabled        bool                 `json:"hmac_enabled"`
	ToolAuditLogs      TableIntegrityReport `json:"tool_audit_logs"`
	ToolAuditResponses TableIntegrityReport `json:"tool_audit_responses"`
	SecurityAuditLogs  TableIntegrityReport `json:"security_audit_logs"`
}

func isLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "lock") || strings.Contains(msg, "conflicting") || strings.Contains(msg, "already open")
}

// VerifyIntegrity verifies persisted hashes across tool_audit_logs, tool_audit_responses, and security_audit_logs.
// If hmacKey is nil, FARADAI_WIRE_AUDIT_HMAC_KEY is checked automatically when needed via ResolveAuditHMACKey unless explicit.
func (e *Engine) VerifyIntegrity(ctx context.Context, hmacKey []byte) (*IntegrityReport, error) {
	if e == nil || e.db == nil {
		return nil, errors.New("telemetry engine is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return verifyDBIntegrity(ctx, e.db, hmacKey)
}

// VerifyDuckDBFile opens a standalone DuckDB file in read-only mode and runs VerifyIntegrity.
func VerifyDuckDBFile(ctx context.Context, dbPath string, hmacKey []byte) (*IntegrityReport, error) {
	if dbPath == "" {
		return nil, errors.New("db path cannot be empty")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("telemetry database not accessible: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	dsn := dbPath + "?access_mode=read_only"
	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		if isLockError(err) {
			return nil, fmt.Errorf("%w: %v", ErrDatabaseLocked, err)
		}
		return nil, fmt.Errorf("failed to open telemetry database: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		if isLockError(err) {
			return nil, fmt.Errorf("%w: %v", ErrDatabaseLocked, err)
		}
		return nil, fmt.Errorf("failed to access telemetry database: %w", err)
	}

	return verifyDBIntegrity(ctx, db, hmacKey)
}

func verifyDBIntegrity(ctx context.Context, db *sql.DB, hmacKey []byte) (*IntegrityReport, error) {
	if len(hmacKey) == 0 {
		hmacKey = ResolveAuditHMACKey()
	}

	report := &IntegrityReport{
		Valid:       true,
		HMACEnabled: len(hmacKey) > 0,
		ToolAuditLogs: TableIntegrityReport{
			TamperedIDs: []string{},
		},
		ToolAuditResponses: TableIntegrityReport{
			TamperedIDs: []string{},
		},
		SecurityAuditLogs: TableIntegrityReport{
			TamperedIDs: []string{},
		},
	}

	toolRep, err := verifyToolAuditLogs(ctx, db, hmacKey)
	if err != nil {
		return nil, err
	}
	report.ToolAuditLogs = toolRep

	if tableExists(ctx, db, "tool_audit_responses") {
		respRep, rErr := verifyToolAuditResponses(ctx, db, hmacKey)
		if rErr != nil {
			return nil, rErr
		}
		report.ToolAuditResponses = respRep
	}

	if tableExists(ctx, db, "security_audit_logs") {
		secRep, sErr := verifySecurityAuditLogs(ctx, db, hmacKey)
		if sErr != nil {
			return nil, sErr
		}
		report.SecurityAuditLogs = secRep
	}

	if report.ToolAuditLogs.TamperedCount > 0 ||
		report.ToolAuditResponses.TamperedCount > 0 ||
		report.SecurityAuditLogs.TamperedCount > 0 ||
		len(report.ToolAuditLogs.TamperedIDs) > 0 ||
		len(report.ToolAuditResponses.TamperedIDs) > 0 ||
		len(report.SecurityAuditLogs.TamperedIDs) > 0 {
		report.Valid = false
	}

	return report, nil
}

func tableExists(ctx context.Context, db *sql.DB, tableName string) bool {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?`, tableName).Scan(&count)
	return err == nil && count > 0
}

func verifyToolAuditLogs(ctx context.Context, db *sql.DB, hmacKey []byte) (TableIntegrityReport, error) {
	rep := TableIntegrityReport{TamperedIDs: []string{}}
	rows, err := db.QueryContext(ctx, `
		SELECT
			id, timestamp, COALESCE(trace_id, ''), agent_name, COALESCE(release_version, ''),
			tool_name, caller_role, COALESCE(user_id, ''), COALESCE(client_ip, ''),
			COALESCE(api_key_id, ''), COALESCE(path_type, ''), decision, COALESCE(matched_rule, ''),
			COALESCE(error_code, 0), COALESCE(error_message, ''), latency_ms,
			COALESCE(raw_payload_preview, ''), COALESCE(original_request, ''), COALESCE(request, ''),
			COALESCE(original_response, ''), COALESCE(response, ''),
			COALESCE(human_approved, FALSE), COALESCE(approved_by, ''), COALESCE(approval_channel, ''),
			COALESCE(NULLIF(hash_version, ''), 'v1'), COALESCE(integrity_hash, '')
		FROM tool_audit_logs
		ORDER BY timestamp ASC
	`)
	if err != nil {
		return rep, fmt.Errorf("query tool_audit_logs for verification: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, traceID, agentName, releaseVer, toolName, callerRole string
			userID, clientIP, apiKeyID, pathType, decision           string
			matchedRule, errMsg, preview, origReq, req               string
			origResp, resp, approvedBy, approvalChannel              string
			hashVer, storedHash                                      string
			ts                                                       time.Time
			errCode                                                  int
			latencyMs                                                float64
			humanApproved                                            bool
		)
		if scanErr := rows.Scan(
			&id, &ts, &traceID, &agentName, &releaseVer,
			&toolName, &callerRole, &userID, &clientIP,
			&apiKeyID, &pathType, &decision, &matchedRule,
			&errCode, &errMsg, &latencyMs,
			&preview, &origReq, &req,
			&origResp, &resp,
			&humanApproved, &approvedBy, &approvalChannel,
			&hashVer, &storedHash,
		); scanErr != nil {
			return rep, fmt.Errorf("scan tool_audit_logs row: %w", scanErr)
		}

		rep.Checked++
		if hashVer == "v1" && !strings.HasPrefix(storedHash, "v2:") {
			expected := ComputeInvocationIntegrityHash(
				id, ts, agentName, toolName, callerRole,
				decision, latencyMs, preview, origReq, req, origResp, resp,
			)
			if subtle.ConstantTimeCompare([]byte(storedHash), []byte(expected)) == 1 {
				rep.LegacyV1++
			} else {
				rep.recordTampered(id)
			}
			continue
		}

		expected, _ := ComputeToolLogHashV2(
			hmacKey,
			id, ts, traceID, agentName, releaseVer, toolName, callerRole,
			userID, clientIP, apiKeyID, pathType, decision, matchedRule,
			errCode, errMsg, latencyMs, preview, origReq, req, origResp, resp,
			humanApproved, approvedBy, approvalChannel,
		)
		if storedHash == "" || subtle.ConstantTimeCompare([]byte(storedHash), []byte(expected)) != 1 {
			rep.recordTampered(id)
		} else {
			rep.V2Verified++
		}
	}
	return rep, rows.Err()
}

func verifyToolAuditResponses(ctx context.Context, db *sql.DB, hmacKey []byte) (TableIntegrityReport, error) {
	rep := TableIntegrityReport{TamperedIDs: []string{}}
	rows, err := db.QueryContext(ctx, `
		SELECT
			invocation_id, COALESCE(trace_id, ''), timestamp, COALESCE(response_decision, ''),
			COALESCE(matched_rule, ''), COALESCE(error_code, 0), COALESCE(audited_rules, ''),
			COALESCE(error_message, ''), latency_ms, COALESCE(output_size_bytes, 0),
			COALESCE(raw_payload_preview, ''), COALESCE(original_payload_preview, ''),
			COALESCE(original_response, ''), COALESCE(response, ''),
			COALESCE(NULLIF(hash_version, ''), 'v1'), COALESCE(integrity_hash, '')
		FROM tool_audit_responses
		ORDER BY timestamp ASC
	`)
	if err != nil {
		return rep, fmt.Errorf("query tool_audit_responses for verification: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			invID, traceID, respDec, matchedRule, auditedRules string
			errMsg, preview, origPreview, origResp, resp       string
			hashVer, storedHash                                string
			ts                                                 time.Time
			errCode, outputBytes                               int
			latencyMs                                          float64
		)
		if scanErr := rows.Scan(
			&invID, &traceID, &ts, &respDec,
			&matchedRule, &errCode, &auditedRules,
			&errMsg, &latencyMs, &outputBytes,
			&preview, &origPreview, &origResp, &resp,
			&hashVer, &storedHash,
		); scanErr != nil {
			return rep, fmt.Errorf("scan tool_audit_responses row: %w", scanErr)
		}

		rep.Checked++
		if hashVer == "v1" && !strings.HasPrefix(storedHash, "v2:") {
			rep.LegacyV1++
			continue
		}

		expected, _ := ComputeToolResponseHashV2(
			hmacKey,
			invID, traceID, ts, respDec, matchedRule,
			errCode, auditedRules, errMsg, latencyMs, outputBytes,
			preview, origPreview, origResp, resp,
		)
		if storedHash == "" || subtle.ConstantTimeCompare([]byte(storedHash), []byte(expected)) != 1 {
			rep.recordTampered(invID)
		} else {
			rep.V2Verified++
		}
	}
	return rep, rows.Err()
}

func verifySecurityAuditLogs(ctx context.Context, db *sql.DB, hmacKey []byte) (TableIntegrityReport, error) {
	rep := TableIntegrityReport{TamperedIDs: []string{}}
	rows, err := db.QueryContext(ctx, `
		SELECT
			id, timestamp, event_type, actor_id, actor_role, COALESCE(client_ip, ''),
			COALESCE(resource_type, ''), COALESCE(resource_id, ''), action, outcome,
			COALESCE(reason, ''), COALESCE(metadata_json, ''),
			COALESCE(NULLIF(hash_version, ''), 'v2'), COALESCE(integrity_hash, '')
		FROM security_audit_logs
		ORDER BY timestamp ASC
	`)
	if err != nil {
		return rep, fmt.Errorf("query security_audit_logs for verification: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, eventType, actorID, actorRole, clientIP string
			resourceType, resourceID, action, outcome   string
			reason, metaJSON, hashVer, storedHash       string
			ts                                          time.Time
		)
		if scanErr := rows.Scan(
			&id, &ts, &eventType, &actorID, &actorRole, &clientIP,
			&resourceType, &resourceID, &action, &outcome,
			&reason, &metaJSON, &hashVer, &storedHash,
		); scanErr != nil {
			return rep, fmt.Errorf("scan security_audit_logs row: %w", scanErr)
		}

		rep.Checked++
		_ = hashVer
		expected, _ := ComputeSecurityHashV2(
			hmacKey,
			id, ts, eventType, actorID, actorRole, clientIP,
			resourceType, resourceID, action, outcome, reason, metaJSON,
		)
		if storedHash == "" || subtle.ConstantTimeCompare([]byte(storedHash), []byte(expected)) != 1 {
			rep.recordTampered(id)
		} else {
			rep.V2Verified++
		}
	}
	return rep, rows.Err()
}
