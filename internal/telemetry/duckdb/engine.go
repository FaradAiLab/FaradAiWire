package duckdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	_ "github.com/marcboeker/go-duckdb"
)

// flushBarrier is an in-band synchronization token sent through eventChan.
type flushBarrier struct {
	done chan struct{}
}

// eventOrBarrier encapsulates an audit event or a flush barrier token.
type eventOrBarrier struct {
	event   *filter.AuditEvent
	barrier *flushBarrier
}

// Engine represents an embedded DuckDB telemetry engine with an asynchronous write-behind buffer.
type Engine struct {
	db            *sql.DB
	ownedDB       bool
	cfg           Config
	eventChan     chan eventOrBarrier
	done          chan struct{}
	wg            sync.WaitGroup
	retention     *RetentionCleaner
	droppedEvents uint64
	isClosed      atomic.Bool
}

// New creates and initializes a new embedded DuckDB telemetry engine.
func New(cfg Config) (*Engine, error) {
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 14
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = 1024 * 1024 * 1024 // 1 GB
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 64 * 1024 // 64 KB
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.BatchFlushMs <= 0 {
		cfg.BatchFlushMs = 100
	}

	dsn := cfg.DBPath
	if dsn != "" && dsn != ":memory:" {
		dir := filepath.Dir(dsn)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create duckdb telemetry directory: %w", err)
		}
	}

	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb connection: %w", err)
	}

	// Optimize connection pooling for embedded single-process DuckDB
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	engine := &Engine{
		db:        db,
		ownedDB:   true,
		cfg:       cfg,
		eventChan: make(chan eventOrBarrier, cfg.BufferSize),
		done:      make(chan struct{}),
	}

	// Initialize tables and indexes
	if err := engine.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize duckdb schema: %w", err)
	}

	// Start retention maintenance worker
	engine.retention = NewRetentionCleaner(
		db,
		cfg.DBPath,
		cfg.RetentionDays,
		cfg.MaxSizeBytes,
		24*time.Hour,
	)
	engine.retention.Start()

	// Start background write-behind worker
	engine.wg.Add(1)
	go engine.writeLoop()

	return engine, nil
}

// NewWithDB constructs a telemetry Engine sharing an existing *sql.DB connection pool (e.g. from internal/db/duckdb.Manager).
func NewWithDB(db *sql.DB, cfg Config) (*Engine, error) {
	if db == nil {
		return nil, fmt.Errorf("shared *sql.DB cannot be nil")
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 14
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = 1024 * 1024 * 1024 // 1 GB
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 64 * 1024 // 64 KB
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.BatchFlushMs <= 0 {
		cfg.BatchFlushMs = 100
	}

	engine := &Engine{
		db:        db,
		ownedDB:   false,
		cfg:       cfg,
		eventChan: make(chan eventOrBarrier, cfg.BufferSize),
		done:      make(chan struct{}),
	}

	// Initialize telemetry tables and indexes
	if err := engine.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize telemetry duckdb schema: %w", err)
	}

	// Start retention maintenance worker
	engine.retention = NewRetentionCleaner(
		db,
		cfg.DBPath,
		cfg.RetentionDays,
		cfg.MaxSizeBytes,
		24*time.Hour,
	)
	engine.retention.Start()

	// Start background write-behind worker
	engine.wg.Add(1)
	go engine.writeLoop()

	return engine, nil
}

// initSchema creates the required tables and performance indexes for telemetry.
func (e *Engine) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tool_audit_logs (
		id VARCHAR PRIMARY KEY,
		timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		agent_name VARCHAR NOT NULL,
		release_version VARCHAR NOT NULL,
		tool_name VARCHAR NOT NULL,
		caller_role VARCHAR DEFAULT 'default',
		decision VARCHAR NOT NULL,
		matched_rule VARCHAR,
		latency_ms DOUBLE NOT NULL,
		input_size_bytes INTEGER,
		output_size_bytes INTEGER,
		raw_payload_preview TEXT,
		original_payload_preview TEXT,
		integrity_hash VARCHAR NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_tool_audit_logs_timestamp ON tool_audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_tool_audit_logs_decision ON tool_audit_logs(decision);
	CREATE INDEX IF NOT EXISTS idx_tool_audit_logs_agent ON tool_audit_logs(agent_name);
	CREATE INDEX IF NOT EXISTS idx_tool_audit_logs_tool ON tool_audit_logs(tool_name);
	`
	_, err := e.db.Exec(schema)
	if err != nil {
		return err
	}

	// Idempotently ensure original_payload_preview column exists in existing DuckDB files
	_, _ = e.db.Exec("ALTER TABLE tool_audit_logs ADD COLUMN original_payload_preview TEXT;")
	return nil
}

// DB returns the underlying database/sql connection pool.
func (e *Engine) DB() *sql.DB {
	if e == nil {
		return nil
	}
	return e.db
}

// LogEvent implements filter.AuditLogger. It places the event onto a bounded, buffered channel.
// Non-blocking select guarantees < 1ms hot-path latency.
func (e *Engine) LogEvent(event *filter.AuditEvent) {
	if e == nil || event == nil || e.isClosed.Load() {
		return
	}

	select {
	case e.eventChan <- eventOrBarrier{event: event}:
	default:
		// Queue saturated: drop event to protect proxy latency SLA
		atomic.AddUint64(&e.droppedEvents, 1)
		slog.Warn("DuckDB telemetry channel buffer saturated, dropped event to preserve proxy latency")
	}
}

// DroppedEvents returns the count of dropped telemetry events due to buffer saturation.
func (e *Engine) DroppedEvents() uint64 {
	return atomic.LoadUint64(&e.droppedEvents)
}

// writeLoop consumes events from the write-behind channel and batches them into DuckDB.
func (e *Engine) writeLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(time.Duration(e.cfg.BatchFlushMs) * time.Millisecond)
	defer ticker.Stop()

	batch := make([]*filter.AuditEvent, 0, 100)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.flushBatch(batch); err != nil {
			slog.Error("Failed to flush DuckDB telemetry batch", slog.String("error", err.Error()), slog.Int("count", len(batch)))
		}
		// Reset batch keeping underlying allocated capacity to avoid GC churn
		clear(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-e.done:
			// Drain remaining events in channel
			for {
				select {
				case item := <-e.eventChan:
					if item.event != nil {
						batch = append(batch, item.event)
						if len(batch) >= 100 {
							flush()
						}
					}
					if item.barrier != nil {
						flush()
						close(item.barrier.done)
					}
				default:
					flush()
					return
				}
			}

		case item, ok := <-e.eventChan:
			if !ok {
				flush()
				return
			}
			if item.event != nil {
				batch = append(batch, item.event)
				if len(batch) >= 100 {
					flush()
				}
			}
			if item.barrier != nil {
				flush()
				close(item.barrier.done)
			}

		case <-ticker.C:
			flush()
		}
	}
}

// generateUUID returns a random UUID string.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// flushBatch inserts a batch of audit events into DuckDB using a transaction.
func (e *Engine) flushBatch(batch []*filter.AuditEvent) error {
	if len(batch) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO tool_audit_logs (
			id, timestamp, agent_name, release_version, tool_name, caller_role,
			decision, matched_rule, latency_ms, input_size_bytes, output_size_bytes,
			raw_payload_preview, original_payload_preview, integrity_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close()

	for _, ev := range batch {
		id := ev.ID
		if id == "" {
			id = generateUUID()
		}

		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}

		agentName := ev.AgentName
		if agentName == "" {
			agentName = "default"
		}

		releaseVer := ev.ReleaseVersion
		if releaseVer == "" {
			releaseVer = "v1.0.0"
		}

		toolName := ev.ToolName
		if toolName == "" {
			toolName = ev.Method
		}

		callerRole := ev.CallerRole
		if callerRole == "" && ev.User != nil {
			callerRole = ev.User.Role
		}
		if callerRole == "" {
			callerRole = "default"
		}

		decision := ev.Decision
		if decision == "" {
			decision = "ALLOW"
		}

		matchedRule := ev.MatchedRule
		if matchedRule == "" {
			matchedRule = ev.FilterName
		}

		preview := ev.RawPayload
		if len(preview) > e.cfg.MaxPayloadBytes && !strings.Contains(preview, "[TRUNCATED - Total Size:") {
			preview, _ = TruncateString(preview, e.cfg.MaxPayloadBytes)
		}

		origPreview := ev.OriginalPayload
		if len(origPreview) > e.cfg.MaxPayloadBytes && !strings.Contains(origPreview, "[TRUNCATED - Total Size:") {
			origPreview, _ = TruncateString(origPreview, e.cfg.MaxPayloadBytes)
		}

		hash := ev.IntegrityHash
		if hash == "" {
			hash = ComputeIntegrityHash(id, ts, agentName, toolName, callerRole, decision, ev.LatencyMs, preview)
		}

		_, err := stmt.ExecContext(ctx,
			id,
			ts,
			agentName,
			releaseVer,
			toolName,
			callerRole,
			decision,
			matchedRule,
			ev.LatencyMs,
			ev.InputBytes,
			ev.OutputBytes,
			preview,
			origPreview,
			hash,
		)
		if err != nil {
			slog.Warn("Failed to execute row insert in telemetry batch", slog.String("error", err.Error()))
		}
	}

	return tx.Commit()
}

// QueryAuditLogs retrieves filtered, paginated audit records from DuckDB.
func (e *Engine) QueryAuditLogs(ctx context.Context, f QueryFilter) (*QueryResult, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("telemetry engine not initialized")
	}

	var whereClauses []string
	var args []interface{}

	if strings.TrimSpace(f.Decision) != "" {
		whereClauses = append(whereClauses, "LOWER(decision) = LOWER(?)")
		args = append(args, strings.TrimSpace(f.Decision))
	}
	if strings.TrimSpace(f.AgentName) != "" {
		whereClauses = append(whereClauses, "agent_name = ?")
		args = append(args, strings.TrimSpace(f.AgentName))
	}
	if strings.TrimSpace(f.ToolName) != "" {
		whereClauses = append(whereClauses, "tool_name = ?")
		args = append(args, strings.TrimSpace(f.ToolName))
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

	// 1. Query total count
	countQuery := "SELECT COUNT(*) FROM tool_audit_logs " + whereSQL
	var total int64
	if err := e.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// 2. Query paginated records
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
		SELECT id, timestamp, agent_name, release_version, tool_name, caller_role,
		       decision, matched_rule, latency_ms, input_size_bytes, output_size_bytes,
		       raw_payload_preview, original_payload_preview, integrity_hash
		FROM tool_audit_logs
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	queryArgs := append(args, limit, offset)
	rows, err := e.db.QueryContext(ctx, querySQL, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var records []AuditRecord
	for rows.Next() {
		var r AuditRecord
		var matchedRule sql.NullString
		var inputBytes, outputBytes sql.NullInt32
		var rawPreview, origPreview sql.NullString

		if err := rows.Scan(
			&r.ID,
			&r.Timestamp,
			&r.AgentName,
			&r.ReleaseVersion,
			&r.ToolName,
			&r.CallerRole,
			&r.Decision,
			&matchedRule,
			&r.LatencyMs,
			&inputBytes,
			&outputBytes,
			&rawPreview,
			&origPreview,
			&r.IntegrityHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit log row: %w", err)
		}

		if matchedRule.Valid {
			r.MatchedRule = matchedRule.String
		}
		if inputBytes.Valid {
			r.InputSizeBytes = int(inputBytes.Int32)
		}
		if outputBytes.Valid {
			r.OutputSizeBytes = int(outputBytes.Int32)
		}
		if rawPreview.Valid {
			r.RawPayloadPreview = rawPreview.String
		}
		if origPreview.Valid {
			r.OriginalPayloadPreview = origPreview.String
		}

		// Populate UI compatibility attributes
		r.Method = r.ToolName
		r.Filter = r.MatchedRule
		if r.Filter == "" {
			r.Filter = "security"
		}
		r.Reason = r.MatchedRule
		r.UserContext = map[string]interface{}{
			"user_role": r.CallerRole,
			"user_id":   r.AgentName,
		}

		records = append(records, r)
	}

	return &QueryResult{
		Logs:   records,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// RetentionCleaner returns the underlying retention cleaner instance.
func (e *Engine) RetentionCleaner() *RetentionCleaner {
	return e.retention
}

// Flush forces any queued events to be drained and inserted synchronously using an in-band barrier token.
// If ctx is provided, it respects context cancellation and timeout. If called with no arguments,
// it defaults to a 5-second timeout context.
func (e *Engine) Flush(ctxs ...context.Context) error {
	if e == nil || e.isClosed.Load() {
		return nil
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	// Check if context or engine is already terminated
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return nil
	default:
	}

	barrier := &flushBarrier{
		done: make(chan struct{}),
	}

	// Enqueue barrier token into event channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return nil
	case e.eventChan <- eventOrBarrier{barrier: barrier}:
	}

	// Wait for barrier completion, context cancellation, or engine closure
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return nil
	case <-barrier.done:
		return nil
	}
}

// FlushWithContext is a convenience wrapper for Flush with an explicit context.
func (e *Engine) FlushWithContext(ctx context.Context) error {
	return e.Flush(ctx)
}

// Close drains all queued telemetry events, checkpoints DuckDB, and closes the database.
func (e *Engine) Close() error {
	if !e.isClosed.CompareAndSwap(false, true) {
		return nil
	}

	// Stop accepting new events and signal writeLoop
	close(e.done)
	e.wg.Wait()

	if e.retention != nil {
		e.retention.Stop()
	}

	// Reclaim disk space and finalize WAL
	_, _ = e.db.Exec("CHECKPOINT;")

	if e.ownedDB {
		return e.db.Close()
	}
	return nil
}
