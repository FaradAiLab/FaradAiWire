package duckdb

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
)

func TestTruncation_UnderLimit(t *testing.T) {
	data := []byte("hello world short payload")
	preview, totalLen := TruncatePayload(data, 64*1024)
	if totalLen != len(data) {
		t.Fatalf("expected totalLen %d, got %d", len(data), totalLen)
	}
	if preview != string(data) {
		t.Fatalf("expected preview '%s', got '%s'", string(data), preview)
	}
	if strings.Contains(preview, "[TRUNCATED") {
		t.Fatalf("did not expect truncation trailer")
	}
}

func TestTruncation_OverLimit(t *testing.T) {
	limit := 1024 // 1 KB limit for testing
	data := bytes.Repeat([]byte("A"), 5*1024) // 5 KB

	preview, totalLen := TruncatePayload(data, limit)
	if totalLen != 5*1024 {
		t.Fatalf("expected totalLen 5120, got %d", totalLen)
	}
	if !strings.HasPrefix(preview, strings.Repeat("A", limit)) {
		t.Fatalf("preview does not start with capped bytes")
	}
	if !strings.Contains(preview, "[TRUNCATED - Total Size: 5.00 KB]") {
		t.Fatalf("expected trailer '[TRUNCATED - Total Size: 5.00 KB]', got preview: %s", preview)
	}
}

func TestTruncateReader(t *testing.T) {
	limit := 500
	raw := strings.Repeat("Z", 2000)
	r := strings.NewReader(raw)

	preview, totalLen, err := TruncateReader(r, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if totalLen != 2000 {
		t.Fatalf("expected totalLen 2000, got %d", totalLen)
	}
	if !strings.Contains(preview, "[TRUNCATED") {
		t.Fatalf("expected truncation trailer in reader preview")
	}
}

func TestIntegrityHash(t *testing.T) {
	now := time.Now()
	h1 := ComputeIntegrityHash("1", now, "agentA", "toolX", "admin", "ALLOW", 1.5, "preview")
	h2 := ComputeIntegrityHash("1", now, "agentA", "toolX", "admin", "ALLOW", 1.5, "preview")
	h3 := ComputeIntegrityHash("1", now, "agentA", "toolX", "admin", "BLOCK", 1.5, "preview")

	if h1 == "" || len(h1) != 64 {
		t.Fatalf("expected 64-char hex hash, got %s", h1)
	}
	if h1 != h2 {
		t.Fatalf("expected hashes to be identical for same input")
	}
	if h1 == h3 {
		t.Fatalf("expected hashes to differ for different decisions")
	}
}

func TestEngine_LifecycleAndQueries(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_telemetry.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    1024 * 1024,
		MaxPayloadBytes: 1024,
		BufferSize:      1000,
		BatchFlushMs:    20,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create duckdb engine: %v", err)
	}
	defer engine.Close()

	// Log several events
	events := []*filter.AuditEvent{
		{
			ID:          "event-1",
			Timestamp:   time.Now().Add(-2 * time.Minute),
			AgentName:   "developer",
			Method:      "tools/call",
			ToolName:    "read_file",
			FilterName:  "dlp",
			Decision:    "ALLOW",
			LatencyMs:   2.4,
			RawPayload:  `{"path": "/src/main.go"}`,
			InputBytes:  25,
			OutputBytes: 100,
			User:        &types.UserContext{UserID: "u1", Role: "engineer"},
		},
		{
			ID:          "event-2",
			Timestamp:   time.Now().Add(-1 * time.Minute),
			AgentName:   "developer",
			Method:      "tools/call",
			ToolName:    "delete_database",
			FilterName:  "tool_rules",
			Decision:    "BLOCK",
			LatencyMs:   0.8,
			RawPayload:  `{"confirm": true}`,
			InputBytes:  17,
			OutputBytes: 0,
			User:        &types.UserContext{UserID: "u1", Role: "engineer"},
		},
		{
			ID:          "event-3",
			Timestamp:   time.Now(),
			AgentName:   "auditor",
			Method:      "tools/call",
			ToolName:    "list_tables",
			FilterName:  "pipeline",
			Decision:    "ALLOW",
			LatencyMs:   1.1,
			RawPayload:  `{}`,
			InputBytes:  2,
			OutputBytes: 50,
			User:        &types.UserContext{UserID: "u2", Role: "admin"},
		},
	}

	for _, ev := range events {
		engine.LogEvent(ev)
	}

	// Flush write-behind buffer synchronously using barrier token
	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("failed to flush engine: %v", err)
	}

	ctx := context.Background()

	// 1. Query all
	res, err := engine.QueryAuditLogs(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if res.Total != 3 {
		t.Fatalf("expected total 3, got %d", res.Total)
	}
	if len(res.Logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(res.Logs))
	}
	// Verify descending timestamp order (most recent first)
	if res.Logs[0].ID != "event-3" {
		t.Errorf("expected first log to be event-3, got %s", res.Logs[0].ID)
	}

	// 2. Query filtered by decision
	resBlocked, err := engine.QueryAuditLogs(ctx, QueryFilter{Decision: "BLOCK"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if resBlocked.Total != 1 {
		t.Fatalf("expected 1 blocked log, got %d", resBlocked.Total)
	}
	if resBlocked.Logs[0].ToolName != "delete_database" {
		t.Errorf("expected tool delete_database, got %s", resBlocked.Logs[0].ToolName)
	}

	// 3. Query filtered by agent
	resAuditor, err := engine.QueryAuditLogs(ctx, QueryFilter{AgentName: "auditor"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if resAuditor.Total != 1 {
		t.Fatalf("expected 1 log for auditor, got %d", resAuditor.Total)
	}
	if resAuditor.Logs[0].CallerRole != "admin" {
		t.Errorf("expected caller_role admin, got %s", resAuditor.Logs[0].CallerRole)
	}

	// 4. Test pagination
	resPage, err := engine.QueryAuditLogs(ctx, QueryFilter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(resPage.Logs) != 1 {
		t.Fatalf("expected 1 row in page, got %d", len(resPage.Logs))
	}
	if resPage.Logs[0].ID != "event-2" {
		t.Errorf("expected offset row to be event-2, got %s", resPage.Logs[0].ID)
	}
}

func TestEngine_RetentionSweep(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "retention_test.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    1024 * 1024,
		MaxPayloadBytes: 1024,
		BufferSize:      1000,
		BatchFlushMs:    10,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	// Insert old record (20 days ago) and recent record (1 day ago)
	oldEvent := &filter.AuditEvent{
		ID:         "old-event",
		Timestamp:  time.Now().AddDate(0, 0, -20),
		AgentName:  "agent-old",
		ToolName:   "test_tool",
		Decision:   "ALLOW",
		RawPayload: "ancient log",
	}
	recentEvent := &filter.AuditEvent{
		ID:         "recent-event",
		Timestamp:  time.Now().AddDate(0, 0, -1),
		AgentName:  "agent-new",
		ToolName:   "test_tool",
		Decision:   "ALLOW",
		RawPayload: "fresh log",
	}

	engine.LogEvent(oldEvent)
	engine.LogEvent(recentEvent)

	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	// Before retention
	resBefore, err := engine.QueryAuditLogs(ctx, QueryFilter{})
	if err != nil || resBefore.Total != 2 {
		t.Fatalf("expected 2 logs before retention, got %d (err: %v)", resBefore.Total, err)
	}

	// Trigger retention enforcement
	if err := engine.RetentionCleaner().EnforceRetention(ctx); err != nil {
		t.Fatalf("retention enforcement failed: %v", err)
	}

	// After retention: only recent event should remain
	resAfter, err := engine.QueryAuditLogs(ctx, QueryFilter{})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if resAfter.Total != 1 {
		t.Fatalf("expected 1 log remaining after retention, got %d", resAfter.Total)
	}
	if resAfter.Logs[0].ID != "recent-event" {
		t.Errorf("expected recent-event to survive, got %s", resAfter.Logs[0].ID)
	}
}

func TestEngine_Concurrency_MicroBursts(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrency_telemetry.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    10 * 1024 * 1024,
		MaxPayloadBytes: 2048,
		BufferSize:      10000,
		BatchFlushMs:    20,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	const concurrentGoroutines = 50
	const eventsPerGoroutine = 40
	totalExpected := concurrentGoroutines * eventsPerGoroutine

	var wg sync.WaitGroup
	var maxHotPathDuration time.Duration
	var durMu sync.Mutex

	start := time.Now()

	for g := 0; g < concurrentGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ev := &filter.AuditEvent{
					ID:         fmt.Sprintf("g%d-e%d", routineID, i),
					Timestamp:  time.Now(),
					AgentName:  fmt.Sprintf("agent-%d", routineID),
					ToolName:   "concurrent_exec",
					Decision:   "ALLOW",
					LatencyMs:  0.5,
					RawPayload: fmt.Sprintf(`{"worker": %d, "call": %d}`, routineID, i),
				}

				sendStart := time.Now()
				engine.LogEvent(ev)
				sendDuration := time.Since(sendStart)

				durMu.Lock()
				if sendDuration > maxHotPathDuration {
					maxHotPathDuration = sendDuration
				}
				durMu.Unlock()
			}
		}(g)
	}

	wg.Wait()
	totalBurstTime := time.Since(start)

	t.Logf("Micro-burst sent %d events in %v. Max single LogEvent hot-path latency: %v",
		totalExpected, totalBurstTime, maxHotPathDuration)

	// Invariant: Hot-path LogEvent must NOT block (tolerant of race detector instrumentation)
	if maxHotPathDuration > 50*time.Millisecond {
		t.Errorf("Hot-path latency exceeded threshold: %v", maxHotPathDuration)
	}

	// Synchronously drain and commit all write-behind events via barrier token
	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("failed to flush write-behind engine: %v", err)
	}

	ctx := context.Background()
	res, err := engine.QueryAuditLogs(ctx, QueryFilter{Limit: 500})
	if err != nil {
		t.Fatalf("failed to query audit logs: %v", err)
	}

	if res.Total != int64(totalExpected) {
		t.Fatalf("expected total %d events, got %d", totalExpected, res.Total)
	}
}

func TestEngine_Flush_BarrierToken(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "barrier_test.duckdb")

	// Set a very long batch flush interval (60s) so the ticker never fires during this test
	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    10 * 1024 * 1024,
		MaxPayloadBytes: 2048,
		BufferSize:      1000,
		BatchFlushMs:    60000,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	// Enqueue 5 events (well below batch threshold of 100)
	for i := 0; i < 5; i++ {
		engine.LogEvent(&filter.AuditEvent{
			ID:         fmt.Sprintf("barrier-ev-%d", i),
			Timestamp:  time.Now(),
			AgentName:  "test-agent",
			ToolName:   "barrier_tool",
			Decision:   "ALLOW",
			LatencyMs:  1.0,
			RawPayload: `{"test": true}`,
		})
	}

	// Trigger barrier flush: must commit all 5 events immediately without waiting for the 60s ticker
	flushStart := time.Now()
	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("barrier flush failed: %v", err)
	}
	flushDuration := time.Since(flushStart)

	if flushDuration > 5*time.Second {
		t.Fatalf("barrier flush took unexpectedly long: %v", flushDuration)
	}

	// Verify events are immediately present in DuckDB
	res, err := engine.QueryAuditLogs(context.Background(), QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if res.Total != 5 {
		t.Fatalf("expected 5 events committed by barrier token, got %d", res.Total)
	}
}

func TestEngine_Flush_ContextCancellationAndTimeout(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "timeout_test.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    10 * 1024 * 1024,
		MaxPayloadBytes: 2048,
		BufferSize:      100,
		BatchFlushMs:    100,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	// 1. Pre-canceled context returns context.Canceled immediately
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err = engine.Flush(canceledCtx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// 2. Pre-expired context returns context.DeadlineExceeded immediately
	expiredCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()

	err = engine.Flush(expiredCtx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestEngine_Flush_ConcurrentFlushes(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_flushes.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    10 * 1024 * 1024,
		MaxPayloadBytes: 2048,
		BufferSize:      1000,
		BatchFlushMs:    50,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	const concurrency = 20
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			engine.LogEvent(&filter.AuditEvent{
				ID:         fmt.Sprintf("concurrent-%d", id),
				Timestamp:  time.Now(),
				AgentName:  "agent",
				ToolName:   "tool",
				Decision:   "ALLOW",
				LatencyMs:  1.0,
				RawPayload: `{}`,
			})
			if err := engine.Flush(context.Background()); err != nil {
				t.Errorf("routine %d flush failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	res, err := engine.QueryAuditLogs(context.Background(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if res.Total != int64(concurrency) {
		t.Fatalf("expected %d events, got %d", concurrency, res.Total)
	}
}

func TestEngine_Flush_AfterClose(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "after_close.duckdb")

	cfg := Config{
		DBPath:          dbPath,
		RetentionDays:   14,
		MaxSizeBytes:    10 * 1024 * 1024,
		MaxPayloadBytes: 2048,
		BufferSize:      100,
		BatchFlushMs:    100,
	}

	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Calling Flush on a closed engine must return immediately without blocking or panicking
	err = engine.Flush(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on closed engine flush, got %v", err)
	}
}

