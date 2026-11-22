package duckdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func (e *Engine) initSecurityAuditSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS security_audit_logs (
		id VARCHAR PRIMARY KEY,
		timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		trace_id VARCHAR,
		event_type VARCHAR NOT NULL,
		actor_id VARCHAR NOT NULL,
		actor_role VARCHAR NOT NULL,
		client_ip VARCHAR,
		resource_type VARCHAR,
		resource_id VARCHAR,
		action VARCHAR NOT NULL,
		outcome VARCHAR NOT NULL,
		reason TEXT,
		metadata_json TEXT,
		integrity_hash VARCHAR NOT NULL,
		hash_version VARCHAR NOT NULL DEFAULT 'v2'
	);

	CREATE INDEX IF NOT EXISTS idx_security_audit_logs_ts ON security_audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_security_audit_logs_type ON security_audit_logs(event_type);
	CREATE INDEX IF NOT EXISTS idx_security_audit_logs_actor ON security_audit_logs(actor_id);
	CREATE INDEX IF NOT EXISTS idx_security_audit_logs_outcome ON security_audit_logs(outcome);
	`
	if _, err := e.db.Exec(schema); err != nil {
		return fmt.Errorf("initialize security_audit_logs schema: %w", err)
	}
	return nil
}

// LogSecurityEvent implements filter.SecurityAuditLogger. It places the control-plane
// event onto the bounded write-behind channel without blocking the caller.
func (e *Engine) LogSecurityEvent(event *filter.SecurityAuditEvent) {
	if e == nil || event == nil || e.isClosed.Load() {
		return
	}

	select {
	case e.eventChan <- eventOrBarrier{secEvent: event}:
	default:
		dropped := atomic.AddUint64(&e.droppedEvents, 1)
		if dropped == 1 || dropped == 100 || dropped%1000 == 0 {
			slog.Warn("DuckDB telemetry channel buffer saturated, dropped security audit event",
				slog.Uint64("dropped_total", dropped),
			)
		}
	}
}

func computeQuickSecurityHash(id string, ts time.Time, eventType, actorID, actorRole, clientIP, resourceType, resourceID, action, outcome, reason, metaJSON string) string {
	h := sha256.New()
	for _, field := range []string{
		id, ts.UTC().Format(time.RFC3339Nano), eventType, actorID, actorRole,
		clientIP, resourceType, resourceID, action, outcome, reason, metaJSON,
	} {
		h.Write([]byte(fmt.Sprintf("%d:%s\n", len(field), field)))
	}
	return "v2:sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (e *Engine) flushSecurityBatch(batch []*filter.SecurityAuditEvent) error {
	if len(batch) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin security audit transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO security_audit_logs (
			id, timestamp, trace_id, event_type, actor_id, actor_role, client_ip,
			resource_type, resource_id, action, outcome, reason, metadata_json,
			integrity_hash, hash_version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare security audit insert: %w", err)
	}
	defer stmt.Close()

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		id := ev.ID
		if id == "" {
			id = generateUUID()
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		actorID := strings.TrimSpace(ev.ActorID)
		if actorID == "" {
			actorID = "local-operator"
		}
		actorRole := strings.TrimSpace(ev.ActorRole)
		if actorRole == "" {
			actorRole = "admin"
		}
		var metaJSON string
		if len(ev.Metadata) > 0 {
			if b, mErr := json.Marshal(ev.Metadata); mErr == nil {
				metaJSON = string(b)
			}
		}
		hashVer := ev.HashVersion
		hash := ev.IntegrityHash
		if hash == "" {
			hash = computeQuickSecurityHash(
				id, ts, ev.EventType, actorID, actorRole, ev.ClientIP,
				ev.ResourceType, ev.ResourceID, ev.Action, ev.Outcome, ev.Reason, metaJSON,
			)
			hashVer = "v2"
		} else if hashVer == "" {
			hashVer = "v2"
		}

		if _, execErr := stmt.ExecContext(ctx,
			id,
			ts,
			nullableText(ev.TraceID),
			ev.EventType,
			actorID,
			actorRole,
			nullableText(ev.ClientIP),
			nullableText(ev.ResourceType),
			nullableText(ev.ResourceID),
			ev.Action,
			ev.Outcome,
			nullableText(ev.Reason),
			nullableText(metaJSON),
			hash,
			hashVer,
		); execErr != nil {
			slog.WarnContext(ctx, "Failed to insert security audit log row", slog.String("error", execErr.Error()))
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit security audit batch: %w", err)
	}
	return nil
}

// QuerySecurityAuditLogs retrieves filtered, paginated control-plane security audit events.
func (e *Engine) QuerySecurityAuditLogs(ctx context.Context, f SecurityQueryFilter) (*SecurityQueryResult, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("telemetry engine not initialized")
	}

	var whereClauses []string
	var args []any

	if v := strings.TrimSpace(f.EventType); v != "" {
		whereClauses = append(whereClauses, "UPPER(event_type) = UPPER(?)")
		args = append(args, v)
	}
	if v := strings.TrimSpace(f.ActorID); v != "" {
		whereClauses = append(whereClauses, "actor_id = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(f.Outcome); v != "" {
		whereClauses = append(whereClauses, "UPPER(outcome) = UPPER(?)")
		args = append(args, v)
	}
	if f.Since != nil {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, *f.Until)
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	var total int64
	if err := e.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_audit_logs "+whereSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count security audit logs: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT id, timestamp, trace_id, event_type, actor_id, actor_role, client_ip,
		       resource_type, resource_id, action, outcome, reason, metadata_json,
		       hash_version, integrity_hash
		FROM security_audit_logs
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	queryArgs := append(args, limit, offset)
	rows, err := e.db.QueryContext(ctx, querySQL, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query security audit logs: %w", err)
	}
	defer rows.Close()

	var events []SecurityAuditRecord
	for rows.Next() {
		var r SecurityAuditRecord
		var traceID, clientIP, resType, resID, reason, metaJSON, hashVer sql.NullString
		if scanErr := rows.Scan(
			&r.ID,
			&r.Timestamp,
			&traceID,
			&r.EventType,
			&r.ActorID,
			&r.ActorRole,
			&clientIP,
			&resType,
			&resID,
			&r.Action,
			&r.Outcome,
			&reason,
			&metaJSON,
			&hashVer,
			&r.IntegrityHash,
		); scanErr != nil {
			return nil, fmt.Errorf("scan security audit row: %w", scanErr)
		}
		if traceID.Valid {
			r.TraceID = traceID.String
		}
		if clientIP.Valid {
			r.ClientIP = clientIP.String
		}
		if resType.Valid {
			r.ResourceType = resType.String
		}
		if resID.Valid {
			r.ResourceID = resID.String
		}
		if reason.Valid {
			r.Reason = reason.String
		}
		if hashVer.Valid {
			r.HashVersion = hashVer.String
		}
		if metaJSON.Valid && metaJSON.String != "" {
			var m map[string]any
			if jErr := json.Unmarshal([]byte(metaJSON.String), &m); jErr == nil {
				r.Metadata = m
			}
		}
		events = append(events, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate security audit rows: %w", err)
	}

	return &SecurityQueryResult{
		Events: events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}
