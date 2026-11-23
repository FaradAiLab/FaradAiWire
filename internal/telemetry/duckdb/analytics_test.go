package duckdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestQueryAuditLogs_PushdownDateRuleAndMetadataOnlySearch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pushdown.duckdb")
	eng, err := New(Config{DBPath: dbPath, BufferSize: 50, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	base := time.Now().UTC().Truncate(time.Second)

	// Old event outside [since, until]
	eng.LogEvent(&filter.AuditEvent{
		ID:              "inv-old",
		TraceID:         "tr-old",
		Timestamp:       base.Add(-2 * time.Hour),
		AgentName:       "alpha",
		ToolName:        "read_file",
		Phase:           filter.AuditPhaseRequest,
		Decision:        filter.DecisionAllowed,
		RequestDecision: filter.DecisionAllowed,
		MatchedRule:     "allow_rule",
		OriginalRequest: "TOP_SECRET_PAYLOAD_DO_NOT_SEARCH_ME",
		Request:         "masked_req",
	})
	// Target event inside window with response-phase block overriding PENDING
	eng.LogEvent(&filter.AuditEvent{
		ID:              "inv-hit",
		TraceID:         "tr-hit",
		Timestamp:       base.Add(-10 * time.Minute),
		AgentName:       "beta",
		ToolName:        "sql_query",
		Phase:           filter.AuditPhaseRequest,
		Decision:        filter.DecisionPending,
		RequestDecision: filter.DecisionAllowed,
		MatchedRule:     "req_dlp",
		OriginalRequest: "secret_payload_only_token",
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:               "inv-hit",
		TraceID:          "tr-hit",
		Timestamp:        base.Add(-9 * time.Minute),
		AgentName:        "beta",
		ToolName:         "sql_query",
		Phase:            filter.AuditPhaseResponse,
		Decision:         filter.DecisionBlocked,
		ResponseDecision: filter.DecisionBlocked,
		MatchedRule:      "credit_card",
		ErrorMessage:     "blocked credit card leak metadata_marker",
	})

	if err := eng.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	since := base.Add(-30 * time.Minute)
	until := base

	// 1. Date range pushdown excludes inv-old
	resRange, err := eng.QueryAuditLogs(context.Background(), QueryFilter{Since: &since, Until: &until})
	if err != nil {
		t.Fatalf("QueryAuditLogs(since, until): %v", err)
	}
	if resRange.Total != 1 || resRange.Logs[0].ID != "inv-hit" {
		t.Fatalf("expected 1 record inv-hit in range, got total=%d logs=%+v", resRange.Total, resRange.Logs)
	}

	// 2. MatchedRule matches response-merged rule "credit_card" (case-insensitive)
	resRule, err := eng.QueryAuditLogs(context.Background(), QueryFilter{MatchedRule: "CREDIT_CARD"})
	if err != nil {
		t.Fatalf("QueryAuditLogs(MatchedRule): %v", err)
	}
	if resRule.Total != 1 || resRule.Logs[0].ID != "inv-hit" {
		t.Fatalf("expected credit_card rule match on inv-hit, got %+v", resRule.Logs)
	}

	// 3. Metadata-only q matches error_message/tool_name, NEVER payload columns
	resMeta, err := eng.QueryAuditLogs(context.Background(), QueryFilter{Search: "metadata_marker"})
	if err != nil {
		t.Fatalf("QueryAuditLogs(Search metadata): %v", err)
	}
	if resMeta.Total != 1 || resMeta.Logs[0].ID != "inv-hit" {
		t.Fatalf("expected metadata search hit for metadata_marker, got %+v", resMeta.Logs)
	}

	resPayloadLeak, err := eng.QueryAuditLogs(context.Background(), QueryFilter{Search: "TOP_SECRET_PAYLOAD"})
	if err != nil {
		t.Fatalf("QueryAuditLogs(Search payload): %v", err)
	}
	if resPayloadLeak.Total != 0 {
		t.Fatalf("metadata-only search must NOT scan payload columns, got %d hits", resPayloadLeak.Total)
	}
}

func TestGetAnalyticsSummary_MetricsAnd5sCache(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "analytics.duckdb")
	eng, err := New(Config{DBPath: dbPath, BufferSize: 50, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	now := time.Now().UTC()
	eng.LogEvent(&filter.AuditEvent{
		ID:        "a-1",
		Timestamp: now.Add(-5 * time.Minute),
		AgentName: "agent-a",
		ToolName:  "read_file",
		Decision:  filter.DecisionAllowed,
		LatencyMs: 10,
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:          "a-2",
		Timestamp:   now.Add(-4 * time.Minute),
		AgentName:   "agent-a",
		ToolName:    "exec_cmd",
		Decision:    filter.DecisionBlocked,
		MatchedRule: "guard",
		LatencyMs:   30,
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:          "a-3",
		Timestamp:   now.Add(-3 * time.Minute),
		AgentName:   "agent-a",
		ToolName:    "exec_cmd",
		Decision:    filter.DecisionMasked,
		MatchedRule: "email",
		LatencyMs:   20,
	})
	// Old event outside 1h window
	eng.LogEvent(&filter.AuditEvent{
		ID:        "a-old",
		Timestamp: now.Add(-3 * time.Hour),
		AgentName: "agent-a",
		ToolName:  "read_file",
		Decision:  filter.DecisionAllowed,
		LatencyMs: 100,
	})
	if err := eng.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	ctx := context.Background()
	sum1, err := eng.GetAnalyticsSummary(ctx, "1h")
	if err != nil {
		t.Fatalf("GetAnalyticsSummary(1h): %v", err)
	}
	if sum1.TotalCalls != 3 || sum1.AllowedCount != 1 || sum1.BlockedCount != 1 || sum1.MaskedCount != 1 {
		t.Fatalf("unexpected counts for 1h window: %+v", sum1)
	}
	if sum1.BlockRate <= 0.30 || sum1.BlockRate >= 0.35 {
		t.Fatalf("expected ~0.333 block_rate, got %v", sum1.BlockRate)
	}
	if sum1.P50LatencyMS != 20 {
		t.Fatalf("expected p50 == 20, got %v", sum1.P50LatencyMS)
	}
	if len(sum1.TopTools) == 0 || sum1.TopTools[0].ToolName != "exec_cmd" || sum1.TopTools[0].Count != 2 {
		t.Fatalf("expected exec_cmd top tool count=2, got %+v", sum1.TopTools)
	}

	// Insert a 4th event and confirm cached 1h result still returns 3 within 5s TTL
	eng.LogEvent(&filter.AuditEvent{
		ID:        "a-4",
		Timestamp: now.Add(-1 * time.Minute),
		AgentName: "agent-a",
		ToolName:  "read_file",
		Decision:  filter.DecisionAllowed,
		LatencyMs: 5,
	})
	if err := eng.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	sumCached, err := eng.GetAnalyticsSummary(ctx, "1h")
	if err != nil {
		t.Fatalf("GetAnalyticsSummary(cached 1h): %v", err)
	}
	if sumCached.TotalCalls != 3 {
		t.Fatalf("expected 5s TTL cache to serve TotalCalls=3, got %d", sumCached.TotalCalls)
	}

	// 24h window isn't cached yet so it sees all 4 events
	sum24h, err := eng.GetAnalyticsSummary(ctx, "24h")
	if err != nil {
		t.Fatalf("GetAnalyticsSummary(24h): %v", err)
	}
	if sum24h.TotalCalls != 5 {
		t.Fatalf("expected 5 total events in 24h window (3 recent + 1 old + a-4), got %d", sum24h.TotalCalls)
	}
}
