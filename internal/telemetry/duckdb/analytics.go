package duckdb

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

const analyticsCacheTTL = 5 * time.Second

// RuleHitCount summarizes invocation counts attributed to a matched rule.
type RuleHitCount struct {
	Rule  string `json:"rule"`
	Count int64  `json:"count"`
}

// ToolCallCount summarizes invocation counts by tool name.
type ToolCallCount struct {
	ToolName string `json:"tool_name"`
	Count    int64  `json:"count"`
}

// AnalyticsSummary provides aggregated local telemetry stats for a bounded time window.
type AnalyticsSummary struct {
	Window       string          `json:"window"`
	GeneratedAt  time.Time       `json:"generated_at"`
	TotalCalls   int64           `json:"total_calls"`
	AllowedCount int64           `json:"allowed_count"`
	BlockedCount int64           `json:"blocked_count"`
	MaskedCount  int64           `json:"masked_count"`
	AuditCount   int64           `json:"audit_count"`
	ErrorCount   int64           `json:"error_count"`
	BlockRate    float64         `json:"block_rate"`
	P50LatencyMS float64         `json:"p50_latency_ms"`
	P95LatencyMS float64         `json:"p95_latency_ms"`
	P99LatencyMS float64         `json:"p99_latency_ms"`
	TopRules     []RuleHitCount  `json:"top_rules"`
	TopTools     []ToolCallCount `json:"top_tools"`
}

type cachedAnalyticsEntry struct {
	expiresAt time.Time
	summary   *AnalyticsSummary
}

func normalizeAnalyticsWindow(raw string) (string, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1h":
		return "1h", time.Hour
	case "7d":
		return "7d", 7 * 24 * time.Hour
	default:
		return "24h", 24 * time.Hour
	}
}

func cloneAnalyticsSummary(in *AnalyticsSummary) *AnalyticsSummary {
	if in == nil {
		return nil
	}
	cp := *in
	cp.TopRules = slices.Clone(in.TopRules)
	cp.TopTools = slices.Clone(in.TopTools)
	return &cp
}

// GetAnalyticsSummary computes local traffic counts, latency percentiles, and top rules/tools
// over "1h", "24h", or "7d", serving repeat queries within 5s from an in-memory cache.
func (e *Engine) GetAnalyticsSummary(ctx context.Context, window string) (*AnalyticsSummary, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("telemetry engine not initialized")
	}

	normWindow, dur := normalizeAnalyticsWindow(window)
	now := time.Now().UTC()

	e.analyticsMu.Lock()
	if e.analyticsCache != nil {
		if entry, ok := e.analyticsCache[normWindow]; ok && now.Before(entry.expiresAt) && entry.summary != nil {
			cached := cloneAnalyticsSummary(entry.summary)
			e.analyticsMu.Unlock()
			return cached, nil
		}
	}
	e.analyticsMu.Unlock()

	since := now.Add(-dur)
	cteSQL := buildConsolidatedAuditCTE("WHERE timestamp >= ?")

	var (
		totalCalls    int64
		allowedCount  int64
		blockedCount  int64
		maskedCount   int64
		auditCount    int64
		errorCount    int64
		p50, p95, p99 float64
	)

	aggSQL := cteSQL + `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN UPPER(decision) = 'ALLOWED' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN UPPER(decision) IN ('BLOCKED', 'CRITICAL') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN UPPER(decision) = 'MASKED' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN UPPER(decision) = 'AUDIT' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN UPPER(decision) = 'ERROR' THEN 1 ELSE 0 END), 0),
			COALESCE(QUANTILE_CONT(latency_ms, 0.50), 0),
			COALESCE(QUANTILE_CONT(latency_ms, 0.95), 0),
			COALESCE(QUANTILE_CONT(latency_ms, 0.99), 0)
		FROM consolidated
	`
	if err := e.db.QueryRowContext(ctx, aggSQL, since).Scan(
		&totalCalls,
		&allowedCount,
		&blockedCount,
		&maskedCount,
		&auditCount,
		&errorCount,
		&p50,
		&p95,
		&p99,
	); err != nil {
		return nil, fmt.Errorf("failed to compute analytics summary: %w", err)
	}

	blockRate := 0.0
	if totalCalls > 0 {
		blockRate = math.Round((float64(blockedCount)/float64(totalCalls))*10000) / 10000
	}

	topRules := []RuleHitCount{}
	ruleRows, err := e.db.QueryContext(ctx, cteSQL+`
		SELECT matched_rule, COUNT(*) AS cnt
		FROM consolidated
		WHERE COALESCE(matched_rule, '') <> ''
		GROUP BY matched_rule
		ORDER BY cnt DESC, matched_rule ASC
		LIMIT 10
	`, since)
	if err != nil {
		return nil, fmt.Errorf("failed to query top rules: %w", err)
	}
	for ruleRows.Next() {
		var rc RuleHitCount
		if scanErr := ruleRows.Scan(&rc.Rule, &rc.Count); scanErr != nil {
			ruleRows.Close()
			return nil, fmt.Errorf("failed to scan top rule: %w", scanErr)
		}
		topRules = append(topRules, rc)
	}
	if err := ruleRows.Err(); err != nil {
		ruleRows.Close()
		return nil, fmt.Errorf("failed iterating top rules: %w", err)
	}
	ruleRows.Close()

	topTools := []ToolCallCount{}
	toolRows, err := e.db.QueryContext(ctx, cteSQL+`
		SELECT tool_name, COUNT(*) AS cnt
		FROM consolidated
		WHERE COALESCE(tool_name, '') <> ''
		GROUP BY tool_name
		ORDER BY cnt DESC, tool_name ASC
		LIMIT 10
	`, since)
	if err != nil {
		return nil, fmt.Errorf("failed to query top tools: %w", err)
	}
	for toolRows.Next() {
		var tc ToolCallCount
		if scanErr := toolRows.Scan(&tc.ToolName, &tc.Count); scanErr != nil {
			toolRows.Close()
			return nil, fmt.Errorf("failed to scan top tool: %w", scanErr)
		}
		topTools = append(topTools, tc)
	}
	if err := toolRows.Err(); err != nil {
		toolRows.Close()
		return nil, fmt.Errorf("failed iterating top tools: %w", err)
	}
	toolRows.Close()

	summary := &AnalyticsSummary{
		Window:       normWindow,
		GeneratedAt:  now,
		TotalCalls:   totalCalls,
		AllowedCount: allowedCount,
		BlockedCount: blockedCount,
		MaskedCount:  maskedCount,
		AuditCount:   auditCount,
		ErrorCount:   errorCount,
		BlockRate:    blockRate,
		P50LatencyMS: math.Round(p50*100) / 100,
		P95LatencyMS: math.Round(p95*100) / 100,
		P99LatencyMS: math.Round(p99*100) / 100,
		TopRules:     topRules,
		TopTools:     topTools,
	}

	e.analyticsMu.Lock()
	if e.analyticsCache == nil {
		e.analyticsCache = make(map[string]cachedAnalyticsEntry)
	}
	e.analyticsCache[normWindow] = cachedAnalyticsEntry{
		expiresAt: time.Now().UTC().Add(analyticsCacheTTL),
		summary:   cloneAnalyticsSummary(summary),
	}
	e.analyticsMu.Unlock()

	return summary, nil
}
