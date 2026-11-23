package duckdb

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	_ "github.com/marcboeker/go-duckdb"
)

// flushBarrier is an in-band synchronization token sent through eventChan.
type flushBarrier struct {
	done chan struct{}
}

// eventOrBarrier encapsulates an audit event, a control-plane security event, or a flush barrier token.
type eventOrBarrier struct {
	event    *filter.AuditEvent
	secEvent *filter.SecurityAuditEvent
	barrier  *flushBarrier
}

// Engine represents an embedded DuckDB telemetry engine with an asynchronous write-behind buffer.
type Engine struct {
	db             *sql.DB
	ownedDB        bool
	cfg            Config
	settingsCache  atomic.Pointer[settings.Cache]
	eventChan      chan eventOrBarrier
	done           chan struct{}
	wg             sync.WaitGroup
	retention      *RetentionCleaner
	droppedEvents  uint64
	isClosed       atomic.Bool
	analyticsMu    sync.Mutex
	analyticsCache map[string]cachedAnalyticsEntry
}

// New creates and initializes a new embedded DuckDB telemetry engine.
func New(cfg Config) (*Engine, error) {
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = 1024 * 1024 * 1024 // 1 GB
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 512 * 1024 // 512 KB
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

	// Start retention maintenance worker (bind live SettingsCache BEFORE initial sweep!)
	engine.retention = NewRetentionCleaner(
		db,
		cfg.DBPath,
		cfg.RetentionDays,
		cfg.MaxSizeBytes,
		24*time.Hour,
	)
	if cfg.SettingsCache != nil {
		engine.SetSettingsCache(cfg.SettingsCache)
	}
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
		cfg.RetentionDays = 30
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = 1024 * 1024 * 1024 // 1 GB
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 512 * 1024 // 512 KB
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

	// Start retention maintenance worker (bind live SettingsCache BEFORE initial sweep!)
	engine.retention = NewRetentionCleaner(
		db,
		cfg.DBPath,
		cfg.RetentionDays,
		cfg.MaxSizeBytes,
		24*time.Hour,
	)
	if cfg.SettingsCache != nil {
		engine.SetSettingsCache(cfg.SettingsCache)
	}
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
		trace_id VARCHAR,
		agent_name VARCHAR NOT NULL,
		release_version VARCHAR NOT NULL,
		tool_name VARCHAR NOT NULL,
		caller_role VARCHAR DEFAULT 'default',
		user_id VARCHAR,
		client_ip VARCHAR,
		api_key_id VARCHAR,
		path_type VARCHAR,
		decision VARCHAR NOT NULL,
		request_decision VARCHAR,
		response_decision VARCHAR,
		matched_rule VARCHAR,
		error_code INTEGER,
		audited_rules TEXT,
		human_approved BOOLEAN DEFAULT FALSE,
		approved_by VARCHAR,
		approval_channel VARCHAR,
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
		hash_version VARCHAR DEFAULT 'v1',
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

	// Idempotently ensure extended columns exist in existing DuckDB files
	alterColumns := []string{
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS original_payload_preview TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS trace_id VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS request_decision VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS response_decision VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS error_message TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS original_request TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS request TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS original_response TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS response TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS user_id VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS client_ip VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS api_key_id VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS path_type VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS error_code INTEGER;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS audited_rules TEXT;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS human_approved BOOLEAN DEFAULT FALSE;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS approved_by VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS approval_channel VARCHAR;",
		"ALTER TABLE tool_audit_logs ADD COLUMN IF NOT EXISTS hash_version VARCHAR DEFAULT 'v1';",
	}
	for _, stmt := range alterColumns {
		if _, aErr := e.db.Exec(stmt); aErr != nil {
			slog.Debug("Optional audit schema migration statement note", slog.String("stmt", stmt), slog.String("info", aErr.Error()))
		}
	}
	_, _ = e.db.Exec("CREATE INDEX IF NOT EXISTS idx_tool_audit_logs_trace_id ON tool_audit_logs(trace_id);")

	// Append-only egress completion table avoids DuckDB ART primary-key UPDATE limitations
	respSchema := `
	CREATE TABLE IF NOT EXISTS tool_audit_responses (
		invocation_id VARCHAR NOT NULL,
		trace_id VARCHAR,
		timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		response_decision VARCHAR,
		matched_rule VARCHAR,
		error_code INTEGER,
		audited_rules TEXT,
		error_message TEXT,
		latency_ms DOUBLE NOT NULL DEFAULT 0,
		output_size_bytes INTEGER,
		raw_payload_preview TEXT,
		original_payload_preview TEXT,
		original_response TEXT,
		response TEXT,
		integrity_hash VARCHAR,
		hash_version VARCHAR DEFAULT 'v1'
	);
	CREATE INDEX IF NOT EXISTS idx_tool_audit_responses_inv ON tool_audit_responses(invocation_id);
	CREATE INDEX IF NOT EXISTS idx_tool_audit_responses_ts ON tool_audit_responses(timestamp);
	`
	if _, err := e.db.Exec(respSchema); err != nil {
		return fmt.Errorf("failed to initialize tool_audit_responses table: %w", err)
	}
	for _, stmt := range []string{
		"ALTER TABLE tool_audit_responses ADD COLUMN IF NOT EXISTS error_code INTEGER;",
		"ALTER TABLE tool_audit_responses ADD COLUMN IF NOT EXISTS audited_rules TEXT;",
		"ALTER TABLE tool_audit_responses ADD COLUMN IF NOT EXISTS integrity_hash VARCHAR;",
		"ALTER TABLE tool_audit_responses ADD COLUMN IF NOT EXISTS hash_version VARCHAR DEFAULT 'v1';",
	} {
		if _, aErr := e.db.Exec(stmt); aErr != nil {
			slog.Debug("Optional response audit schema migration note", slog.String("stmt", stmt), slog.String("info", aErr.Error()))
		}
	}

	return e.initSecurityAuditSchema()
}

// DB returns the underlying database/sql connection pool.
func (e *Engine) DB() *sql.DB {
	if e == nil {
		return nil
	}
	return e.db
}

// SetSettingsCache attaches an atomic operational settings cache to the telemetry engine
// and its retention cleaner so preview ceilings and retention days update without restarts.
func (e *Engine) SetSettingsCache(cache *settings.Cache) {
	if e == nil {
		return
	}
	e.settingsCache.Store(cache)
	if e.retention != nil {
		e.retention.SetSettingsCache(cache)
	}
}

func (e *Engine) effectiveMaxPayloadBytes() int {
	limit := e.cfg.MaxPayloadBytes
	if cache := e.settingsCache.Load(); cache != nil {
		if s := cache.Get(); s != nil && s.Limits.MaxPreviewBytes >= 65536 {
			limit = s.Limits.MaxPreviewBytes
		}
	}
	if limit <= 0 {
		limit = 512 * 1024
	}
	return limit
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
		dropped := atomic.AddUint64(&e.droppedEvents, 1)
		if dropped == 1 || dropped == 100 || dropped%1000 == 0 {
			slog.Warn("DuckDB telemetry channel buffer saturated, dropped event to preserve proxy latency",
				slog.Uint64("dropped_total", dropped),
			)
		}
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
	secBatch := make([]*filter.SecurityAuditEvent, 0, 100)

	flush := func() {
		if len(batch) > 0 {
			if err := e.flushBatch(batch); err != nil {
				slog.Error("Failed to flush DuckDB telemetry batch", slog.String("error", err.Error()), slog.Int("count", len(batch)))
			}
			clear(batch)
			batch = batch[:0]
		}
		if len(secBatch) > 0 {
			if err := e.flushSecurityBatch(secBatch); err != nil {
				slog.Error("Failed to flush DuckDB security audit batch", slog.String("error", err.Error()), slog.Int("count", len(secBatch)))
			}
			clear(secBatch)
			secBatch = secBatch[:0]
		}
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
					if item.secEvent != nil {
						secBatch = append(secBatch, item.secEvent)
						if len(secBatch) >= 100 {
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
			if item.secEvent != nil {
				secBatch = append(secBatch, item.secEvent)
				if len(secBatch) >= 100 {
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

// boundAuditField enforces maxLen truncation on stored telemetry payloads while avoiding double truncation.
func boundAuditField(val string, maxLen int) string {
	if val == "" || maxLen <= 0 {
		return val
	}
	if len(val) > maxLen && !strings.Contains(val, "[TRUNCATED - Total Size:") {
		truncated, _ := TruncateString(val, maxLen)
		return truncated
	}
	return val
}

func mergeMatchedRules(existingRule, newRule string) string {
	if existingRule == "" {
		return newRule
	}
	if newRule == "" || newRule == existingRule {
		return existingRule
	}
	return existingRule + "," + newRule
}

type normalizedEventFields struct {
	id              string
	ts              time.Time
	traceID         string
	agentName       string
	releaseVer      string
	toolName        string
	callerRole      string
	userID          string
	clientIP        string
	apiKeyID        string
	pathType        string
	decision        string
	reqDecision     string
	respDecision    string
	matchedRule     string
	errorCode       int
	auditedRules    string
	humanApproved   bool
	approvedBy      string
	approvalChannel string
	errorMsg        string
	preview         string
	origPreview     string
	origReq         string
	req             string
	origResp        string
	resp            string
	hashVersion     string
}

func encodeAuditedRules(rules []string) string {
	if len(rules) == 0 {
		return ""
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return ""
	}
	return string(b)
}

func decodeAuditedRules(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, "\n") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var arr []string
		if err := json.Unmarshal([]byte(part), &arr); err == nil {
			for _, r := range arr {
				if r != "" && !slices.Contains(out, r) {
					out = append(out, r)
				}
			}
			continue
		}
		for _, r := range strings.Split(part, ",") {
			r = strings.TrimSpace(r)
			if r != "" && !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out
}

func (e *Engine) normalizeEvent(ev *filter.AuditEvent, maxBytes int) normalizedEventFields {
	id := ev.ID
	if id == "" {
		id = generateUUID()
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	ts = ts.UTC().Truncate(time.Microsecond)
	agentName := ev.AgentName
	if agentName == "" {
		agentName = "default"
	}
	releaseVer := ev.ReleaseVersion
	if releaseVer == "" {
		releaseVer = config.GetVersion()
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
	userID := ""
	if ev.User != nil {
		userID = strings.TrimSpace(ev.User.UserID)
	}
	apiKeyID := strings.TrimSpace(ev.APIKeyID)
	if apiKeyID == "" && ev.User != nil {
		apiKeyID = strings.TrimSpace(ev.User.APIKeyID)
	}
	clientIP := strings.TrimSpace(ev.ClientIP)
	if clientIP == "" && ev.User != nil {
		clientIP = strings.TrimSpace(ev.User.ClientIP)
	}
	decision := ev.Decision
	if decision == "" {
		decision = filter.DecisionAllowed
	}
	matchedRule := ev.MatchedRule
	if matchedRule == "" {
		matchedRule = ev.FilterName
	}
	errorMsg := ev.ErrorMessage
	if errorMsg == "" && (strings.EqualFold(decision, filter.DecisionBlocked) || strings.EqualFold(decision, filter.DecisionCritical)) {
		errorMsg = ev.Message
	}
	hashVersion := ev.HashVersion
	if hashVersion == "" {
		hashVersion = "v2"
	}

	return normalizedEventFields{
		id:              id,
		ts:              ts,
		traceID:         ev.TraceID,
		agentName:       agentName,
		releaseVer:      releaseVer,
		toolName:        toolName,
		callerRole:      callerRole,
		userID:          userID,
		clientIP:        clientIP,
		apiKeyID:        apiKeyID,
		pathType:        ev.PathType,
		decision:        decision,
		reqDecision:     ev.RequestDecision,
		respDecision:    ev.ResponseDecision,
		matchedRule:     matchedRule,
		errorCode:       ev.ErrorCode,
		auditedRules:    encodeAuditedRules(ev.AuditedRules),
		humanApproved:   ev.HumanApproved,
		approvedBy:      ev.ApprovedBy,
		approvalChannel: ev.ApprovalChannel,
		errorMsg:        errorMsg,
		preview:         boundAuditField(ev.RawPayload, maxBytes),
		origPreview:     boundAuditField(ev.OriginalPayload, maxBytes),
		origReq:         boundAuditField(ev.OriginalRequest, maxBytes),
		req:             boundAuditField(ev.Request, maxBytes),
		origResp:        boundAuditField(ev.OriginalResponse, maxBytes),
		resp:            boundAuditField(ev.Response, maxBytes),
		hashVersion:     hashVersion,
	}
}

func nullableText(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// flushBatch inserts or upserts a batch of audit events into DuckDB using a transaction.
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

	insertStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO tool_audit_logs (
			id, timestamp, trace_id, agent_name, release_version, tool_name, caller_role,
			user_id, client_ip, api_key_id, path_type,
			decision, request_decision, response_decision, matched_rule, error_code, audited_rules,
			human_approved, approved_by, approval_channel, error_message,
			latency_ms, input_size_bytes, output_size_bytes,
			raw_payload_preview, original_payload_preview,
			original_request, request, original_response, response,
			hash_version, integrity_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer insertStmt.Close()

	insertRespStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO tool_audit_responses (
			invocation_id, trace_id, timestamp, response_decision, matched_rule,
			error_code, audited_rules, error_message, latency_ms, output_size_bytes,
			raw_payload_preview, original_payload_preview, original_response, response,
			integrity_hash, hash_version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare response insert statement: %w", err)
	}
	defer insertRespStmt.Close()

	maxBytes := e.effectiveMaxPayloadBytes()
	hmacKey := ResolveAuditHMACKey()
	seenIDs := make(map[string]struct{}, len(batch))
	seenTraces := make(map[string]string, len(batch))

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		nf := e.normalizeEvent(ev, maxBytes)

		if ev.Phase == filter.AuditPhaseResponse && (ev.ID != "" || nf.traceID != "") {
			var invID string
			if ev.ID != "" {
				if _, ok := seenIDs[ev.ID]; ok {
					invID = ev.ID
				}
			}
			if invID == "" && nf.traceID != "" {
				if mappedID, ok := seenTraces[nf.traceID]; ok {
					invID = mappedID
				}
			}
			if invID == "" {
				invID = e.findExistingInvocationIDInTx(ctx, tx, ev.ID, nf.traceID)
			}
			if invID != "" {
				respDec := nf.respDecision
				if respDec == "" {
					respDec = nf.decision
				}
				respHash := ev.IntegrityHash
				respHashVer := nf.hashVersion
				if respHash == "" {
					respHash, respHashVer = ComputeToolResponseHashV2(
						hmacKey,
						invID, nf.traceID, nf.ts,
						respDec, nf.matchedRule, ev.ErrorCode,
						nf.auditedRules, nf.errorMsg, ev.LatencyMs, ev.OutputBytes,
						nf.preview, nf.origPreview, nf.origResp, nf.resp,
					)
				}
				if _, rErr := insertRespStmt.ExecContext(ctx,
					invID,
					nullableText(nf.traceID),
					nf.ts,
					nullableText(respDec),
					nullableText(nf.matchedRule),
					ev.ErrorCode,
					nullableText(nf.auditedRules),
					nullableText(nf.errorMsg),
					ev.LatencyMs,
					ev.OutputBytes,
					nullableText(nf.preview),
					nullableText(nf.origPreview),
					nullableText(nf.origResp),
					nullableText(nf.resp),
					nullableText(respHash),
					respHashVer,
				); rErr != nil {
					slog.WarnContext(ctx, "Failed to insert response completion record", slog.String("error", rErr.Error()))
				} else {
					continue
				}
			}
		}

		hash := ev.IntegrityHash
		hashVer := nf.hashVersion
		if hash == "" {
			hash, hashVer = ComputeToolLogHashV2(
				hmacKey,
				nf.id, nf.ts, nf.traceID, nf.agentName, nf.releaseVer, nf.toolName, nf.callerRole,
				nf.userID, nf.clientIP, nf.apiKeyID, nf.pathType,
				nf.decision, nf.matchedRule, ev.ErrorCode, nf.errorMsg, ev.LatencyMs,
				nf.preview, nf.origReq, nf.req, nf.origResp, nf.resp,
				nf.humanApproved, nf.approvedBy, nf.approvalChannel,
			)
		}

		_, err := insertStmt.ExecContext(ctx,
			nf.id,
			nf.ts,
			nullableText(nf.traceID),
			nf.agentName,
			nf.releaseVer,
			nf.toolName,
			nf.callerRole,
			nullableText(nf.userID),
			nullableText(nf.clientIP),
			nullableText(nf.apiKeyID),
			nullableText(nf.pathType),
			nf.decision,
			nullableText(nf.reqDecision),
			nullableText(nf.respDecision),
			nullableText(nf.matchedRule),
			ev.ErrorCode,
			nullableText(nf.auditedRules),
			nf.humanApproved,
			nullableText(nf.approvedBy),
			nullableText(nf.approvalChannel),
			nullableText(nf.errorMsg),
			ev.LatencyMs,
			ev.InputBytes,
			ev.OutputBytes,
			nf.preview,
			nullableText(nf.origPreview),
			nullableText(nf.origReq),
			nullableText(nf.req),
			nullableText(nf.origResp),
			nullableText(nf.resp),
			hashVer,
			hash,
		)
		if err != nil {
			slog.WarnContext(ctx, "Failed to execute row insert in telemetry batch", slog.String("error", err.Error()))
		} else {
			seenIDs[nf.id] = struct{}{}
			if nf.traceID != "" {
				seenTraces[nf.traceID] = nf.id
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry batch: %w", err)
	}
	return nil
}

func (e *Engine) findExistingInvocationIDInTx(ctx context.Context, tx *sql.Tx, id, traceID string) string {
	var rowID string
	if id != "" {
		if err := tx.QueryRowContext(ctx, "SELECT id FROM tool_audit_logs WHERE id = ? LIMIT 1", id).Scan(&rowID); err == nil && rowID != "" {
			return rowID
		}
	}
	if traceID != "" {
		if err := tx.QueryRowContext(ctx, "SELECT id FROM tool_audit_logs WHERE trace_id = ? ORDER BY timestamp DESC LIMIT 1", traceID).Scan(&rowID); err == nil && rowID != "" {
			return rowID
		}
	}
	return ""
}

func escapeSQLLike(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(s)
}

func buildConsolidatedAuditCTE(logsWhereSQL string) string {
	return fmt.Sprintf(`
WITH filtered_logs AS (
	SELECT *
	FROM tool_audit_logs
	%s
),
latest_resp AS (
	SELECT DISTINCT ON (invocation_id)
		invocation_id, response_decision, matched_rule, error_code, audited_rules, error_message,
		latency_ms, output_size_bytes, raw_payload_preview, original_payload_preview,
		original_response, response
	FROM tool_audit_responses
	WHERE invocation_id IN (SELECT id FROM filtered_logs)
	ORDER BY invocation_id, timestamp DESC
),
consolidated AS (
	SELECT
		l.id,
		l.timestamp,
		l.trace_id,
		l.agent_name,
		l.release_version,
		l.tool_name,
		l.caller_role,
		l.user_id,
		l.client_ip,
		l.api_key_id,
		l.path_type,
		CASE
			WHEN r.invocation_id IS NULL THEN l.decision
			WHEN 'CRITICAL' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'CRITICAL'
			WHEN 'BLOCKED' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'BLOCKED'
			WHEN 'ERROR' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'ERROR'
			WHEN 'MASKED' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'MASKED'
			WHEN 'AUDIT' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'AUDIT'
			WHEN 'ALLOWED' IN (UPPER(COALESCE(NULLIF(l.request_decision, ''), l.decision)), UPPER(COALESCE(r.response_decision, ''))) THEN 'ALLOWED'
			ELSE COALESCE(NULLIF(r.response_decision, ''), l.decision)
		END AS decision,
		l.request_decision,
		COALESCE(NULLIF(r.response_decision, ''), l.response_decision) AS response_decision,
		CASE
			WHEN COALESCE(l.matched_rule, '') = '' THEN COALESCE(r.matched_rule, '')
			WHEN COALESCE(r.matched_rule, '') = '' OR r.matched_rule = l.matched_rule THEN l.matched_rule
			ELSE l.matched_rule || ',' || r.matched_rule
		END AS matched_rule,
		COALESCE(NULLIF(r.error_code, 0), l.error_code) AS error_code,
		CASE
			WHEN COALESCE(l.audited_rules, '') = '' THEN COALESCE(r.audited_rules, '')
			WHEN COALESCE(r.audited_rules, '') = '' OR r.audited_rules = l.audited_rules THEN l.audited_rules
			ELSE l.audited_rules || CHR(10) || r.audited_rules
		END AS audited_rules,
		COALESCE(l.human_approved, FALSE) AS human_approved,
		l.approved_by,
		l.approval_channel,
		COALESCE(NULLIF(r.error_message, ''), l.error_message) AS error_message,
		l.latency_ms + COALESCE(r.latency_ms, 0) AS latency_ms,
		l.input_size_bytes,
		CASE WHEN r.output_size_bytes IS NOT NULL AND r.output_size_bytes > 0 THEN r.output_size_bytes ELSE l.output_size_bytes END AS output_size_bytes,
		COALESCE(NULLIF(r.raw_payload_preview, ''), l.raw_payload_preview) AS raw_payload_preview,
		COALESCE(l.original_payload_preview, r.original_payload_preview) AS original_payload_preview,
		l.original_request,
		l.request,
		COALESCE(NULLIF(r.original_response, ''), l.original_response) AS original_response,
		COALESCE(NULLIF(r.response, ''), l.response) AS response,
		COALESCE(NULLIF(l.hash_version, ''), 'v1') AS hash_version,
		l.integrity_hash
	FROM filtered_logs l
	LEFT JOIN latest_resp r ON r.invocation_id = l.id
)
`, logsWhereSQL)
}

// QueryAuditLogs retrieves filtered, paginated audit records from DuckDB with predicate pushdown.
func (e *Engine) QueryAuditLogs(ctx context.Context, f QueryFilter) (*QueryResult, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("telemetry engine not initialized")
	}

	// Push table-local predicates down into filtered_logs before joining tool_audit_responses.
	var logClauses []string
	var logArgs []interface{}
	if v := strings.TrimSpace(f.AgentName); v != "" {
		logClauses = append(logClauses, "agent_name = ?")
		logArgs = append(logArgs, v)
	}
	if v := strings.TrimSpace(f.ToolName); v != "" {
		logClauses = append(logClauses, "tool_name = ?")
		logArgs = append(logArgs, v)
	}
	if v := strings.TrimSpace(f.TraceID); v != "" {
		logClauses = append(logClauses, "trace_id = ?")
		logArgs = append(logArgs, v)
	}
	if f.Since != nil {
		logClauses = append(logClauses, "timestamp >= ?")
		logArgs = append(logArgs, *f.Since)
	}
	if f.Until != nil {
		logClauses = append(logClauses, "timestamp <= ?")
		logArgs = append(logArgs, *f.Until)
	}

	logsWhereSQL := ""
	if len(logClauses) > 0 {
		logsWhereSQL = "WHERE " + strings.Join(logClauses, " AND ")
	}

	// Post-merge predicates (values that can be refined by tool_audit_responses).
	var consClauses []string
	var consArgs []interface{}
	if v := strings.TrimSpace(f.Decision); v != "" {
		consClauses = append(consClauses, "LOWER(decision) = LOWER(?)")
		consArgs = append(consArgs, v)
	}
	if v := strings.TrimSpace(f.MatchedRule); v != "" {
		escaped := escapeSQLLike(strings.ToLower(v))
		consClauses = append(consClauses, `(LOWER(matched_rule) = LOWER(?) OR (',' || LOWER(matched_rule) || ',') LIKE ? ESCAPE '\')`)
		consArgs = append(consArgs, v, "%,"+escaped+",%")
	}
	if v := strings.TrimSpace(f.Search); v != "" {
		// Metadata-only search: never scan 512KB-4MB payload columns.
		pattern := "%" + escapeSQLLike(v) + "%"
		consClauses = append(consClauses, `(
			tool_name ILIKE ? ESCAPE '\' OR
			agent_name ILIKE ? ESCAPE '\' OR
			matched_rule ILIKE ? ESCAPE '\' OR
			error_message ILIKE ? ESCAPE '\' OR
			user_id ILIKE ? ESCAPE '\' OR
			trace_id ILIKE ? ESCAPE '\'
		)`)
		consArgs = append(consArgs, pattern, pattern, pattern, pattern, pattern, pattern)
	}

	consWhereSQL := ""
	if len(consClauses) > 0 {
		consWhereSQL = "WHERE " + strings.Join(consClauses, " AND ")
	}

	cteSQL := buildConsolidatedAuditCTE(logsWhereSQL)
	allArgs := make([]interface{}, 0, len(logArgs)+len(consArgs))
	allArgs = append(allArgs, logArgs...)
	allArgs = append(allArgs, consArgs...)

	// 1. Query total count
	countQuery := cteSQL + "SELECT COUNT(*) FROM consolidated " + consWhereSQL
	var total int64
	if err := e.db.QueryRowContext(ctx, countQuery, allArgs...).Scan(&total); err != nil {
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

	selectCols := `
		id, timestamp, trace_id, agent_name, release_version, tool_name, caller_role,
		user_id, client_ip, api_key_id, path_type,
		decision, request_decision, response_decision, matched_rule, error_code, audited_rules,
		human_approved, approved_by, approval_channel, error_message,
		latency_ms, input_size_bytes, output_size_bytes,
		raw_payload_preview, original_payload_preview,
		original_request, request, original_response, response,
		hash_version, integrity_hash`
	if f.SummaryOnly {
		selectCols = `
			id, timestamp, trace_id, agent_name, release_version, tool_name, caller_role,
			user_id, client_ip, api_key_id, path_type,
			decision, request_decision, response_decision, matched_rule, error_code, audited_rules,
			human_approved, approved_by, approval_channel, error_message,
			latency_ms, input_size_bytes, output_size_bytes,
			LEFT(COALESCE(raw_payload_preview, ''), 4096), '',
			'', '', '', '',
			hash_version, integrity_hash`
	}

	querySQL := fmt.Sprintf(`
		%s
		SELECT %s
		FROM consolidated
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, cteSQL, selectCols, consWhereSQL)

	queryArgs := make([]interface{}, 0, len(allArgs)+2)
	queryArgs = append(queryArgs, allArgs...)
	queryArgs = append(queryArgs, limit, offset)
	rows, err := e.db.QueryContext(ctx, querySQL, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var records []AuditRecord
	for rows.Next() {
		r, scanErr := scanAuditRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan audit log row: %w", scanErr)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating audit log rows: %w", err)
	}

	return &QueryResult{
		Logs:   records,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetAuditLogByID retrieves a single complete Tool Invocation Record (including all
// 4 payload lifecycle snapshots) by record ID or trace ID.
func (e *Engine) GetAuditLogByID(ctx context.Context, id string) (*AuditRecord, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("telemetry engine not initialized")
	}
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		return nil, fmt.Errorf("audit log id cannot be empty")
	}

	querySQL := buildConsolidatedAuditCTE("WHERE id = ? OR trace_id = ?") + `
		SELECT id, timestamp, trace_id, agent_name, release_version, tool_name, caller_role,
		       user_id, client_ip, api_key_id, path_type,
		       decision, request_decision, response_decision, matched_rule, error_code, audited_rules,
		       human_approved, approved_by, approval_channel, error_message,
		       latency_ms, input_size_bytes, output_size_bytes,
		       raw_payload_preview, original_payload_preview,
		       original_request, request, original_response, response,
		       hash_version, integrity_hash
		FROM consolidated
		ORDER BY timestamp DESC
		LIMIT 1
	`
	row := e.db.QueryRowContext(ctx, querySQL, cleanID, cleanID)
	rec, err := scanAuditRecord(row)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

type auditRowScanner interface {
	Scan(dest ...any) error
}

func scanAuditRecord(row auditRowScanner) (AuditRecord, error) {
	var r AuditRecord
	var (
		traceID, userID, clientIP, apiKeyID, pathType sql.NullString
		reqDec, respDec, matchedRule, errMsg          sql.NullString
		auditedRules, approvedBy, approvalChannel     sql.NullString
		hashVersion                                   sql.NullString
		errCode                                       sql.NullInt32
		humanApproved                                 sql.NullBool
		inputBytes, outputBytes                       sql.NullInt32
		rawPreview, origPreview                       sql.NullString
		origReq, sentReq, origResp, finalResp         sql.NullString
	)

	if err := row.Scan(
		&r.ID,
		&r.Timestamp,
		&traceID,
		&r.AgentName,
		&r.ReleaseVersion,
		&r.ToolName,
		&r.CallerRole,
		&userID,
		&clientIP,
		&apiKeyID,
		&pathType,
		&r.Decision,
		&reqDec,
		&respDec,
		&matchedRule,
		&errCode,
		&auditedRules,
		&humanApproved,
		&approvedBy,
		&approvalChannel,
		&errMsg,
		&r.LatencyMs,
		&inputBytes,
		&outputBytes,
		&rawPreview,
		&origPreview,
		&origReq,
		&sentReq,
		&origResp,
		&finalResp,
		&hashVersion,
		&r.IntegrityHash,
	); err != nil {
		return AuditRecord{}, err
	}

	if traceID.Valid {
		r.TraceID = traceID.String
	}
	if userID.Valid {
		r.UserID = userID.String
	}
	if clientIP.Valid {
		r.ClientIP = clientIP.String
	}
	if apiKeyID.Valid {
		r.APIKeyID = apiKeyID.String
	}
	if pathType.Valid {
		r.PathType = pathType.String
	}
	if reqDec.Valid {
		r.RequestDecision = reqDec.String
	}
	if respDec.Valid {
		r.ResponseDecision = respDec.String
	}
	if matchedRule.Valid {
		r.MatchedRule = matchedRule.String
	}
	if errCode.Valid {
		r.ErrorCode = int(errCode.Int32)
	}
	if auditedRules.Valid {
		r.AuditedRules = decodeAuditedRules(auditedRules.String)
	}
	if humanApproved.Valid {
		r.HumanApproved = humanApproved.Bool
	}
	if approvedBy.Valid {
		r.ApprovedBy = approvedBy.String
	}
	if approvalChannel.Valid {
		r.ApprovalChannel = approvalChannel.String
	}
	if errMsg.Valid {
		r.ErrorMessage = errMsg.String
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
	if origReq.Valid {
		r.OriginalRequest = origReq.String
	}
	if sentReq.Valid {
		r.Request = sentReq.String
	}
	if origResp.Valid {
		r.OriginalResponse = origResp.String
	}
	if finalResp.Valid {
		r.Response = finalResp.String
	}
	if hashVersion.Valid {
		r.HashVersion = hashVersion.String
	}

	r.Method = r.ToolName
	r.Filter = r.MatchedRule
	if r.Filter == "" {
		r.Filter = "security"
	}
	r.Reason = r.MatchedRule
	if r.ErrorMessage != "" && (strings.EqualFold(r.Decision, "BLOCKED") || strings.EqualFold(r.Decision, "CRITICAL")) {
		r.Reason = r.ErrorMessage
	}
	r.UserContext = map[string]interface{}{
		"user_role": r.CallerRole,
		"user_id":   cmp.Or(r.UserID, r.AgentName),
	}
	if r.APIKeyID != "" {
		r.UserContext["api_key_id"] = r.APIKeyID
	}
	if r.ClientIP != "" {
		r.UserContext["client_ip"] = r.ClientIP
	}
	return r, nil
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
