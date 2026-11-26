package admin

import (
	"context"
	"database/sql"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

// TelemetryIntegrityVerifier runs in-process cryptographic audit integrity checks across DuckDB tables.
type TelemetryIntegrityVerifier interface {
	VerifyIntegrity(ctx context.Context, hmacKey []byte) (*duckdb.IntegrityReport, error)
}

type telemetryDBProvider interface {
	DB() *sql.DB
}

type droppedEventsCounter interface {
	DroppedEvents() uint64
}

func (a *AdminServer) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	hmacKey := duckdb.ResolveAuditHMACKey()
	overallValid := true

	var dbReport *duckdb.IntegrityReport
	if verifier, ok := a.telemetryEngine.(TelemetryIntegrityVerifier); ok && verifier != nil {
		rep, err := verifier.VerifyIntegrity(r.Context(), hmacKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "VERIFY_DUCKDB_FAILED", "Failed to verify DuckDB audit integrity: "+err.Error())
			return
		}
		dbReport = rep
		if !rep.Valid {
			overallValid = false
		}
	}

	var jsonlReport *logger.JSONLVerifyReport
	if cfg := a.Config(); cfg != nil && cfg.AuditLog.Enabled && cfg.AuditLog.Path != "" {
		rep, err := logger.VerifyAuditJSONL(cfg.GetAuditLogPath(), hmacKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "VERIFY_JSONL_FAILED", "Failed to verify JSONL audit integrity: "+err.Error())
			return
		}
		jsonlReport = rep
		if !rep.Valid {
			overallValid = false
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":  overallValid,
		"duckdb": dbReport,
		"jsonl":  jsonlReport,
	})
}

func (a *AdminServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	reg := a.metrics
	if reg == nil {
		reg = metrics.Default()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(reg.RenderPrometheus()))
}

func (a *AdminServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	cfg := a.Config()
	draining := a.isDraining()

	duckHealth, duckOK := a.checkDuckDBHealth(r.Context(), cfg)

	var duckDrops, brokerDrops, jsonlDrops uint64
	if dc, ok := a.telemetryEngine.(droppedEventsCounter); ok && dc != nil {
		duckDrops = dc.DroppedEvents()
	}
	if a.eventBroker != nil {
		brokerDrops = a.eventBroker.DroppedCount()
	}
	if a.auditLogDroppedFn != nil {
		jsonlDrops = a.auditLogDroppedFn()
	}
	totalDrops := duckDrops + brokerDrops + jsonlDrops

	jsonlStatus := "disabled"
	if cfg != nil && cfg.AuditLog.Enabled {
		jsonlStatus = "healthy"
		if jsonlDrops > 0 {
			jsonlStatus = "degraded"
		}
	} else if jsonlDrops > 0 {
		jsonlStatus = "degraded"
	}

	brokerStatus := "disabled"
	if a.eventBroker != nil {
		brokerStatus = "healthy"
		if brokerDrops > 0 {
			brokerStatus = "degraded"
		}
	}

	guardComp := map[string]interface{}{"status": "standby"}
	if a.guardManager == nil {
		guardComp["status"] = "disabled"
	} else {
		if a.guardManager.IsRunning() {
			guardComp["status"] = "healthy"
		}
		if lr, ok := a.guardManager.(guard.LatencyReporter); ok && lr != nil {
			if avg := lr.AverageLatencyMS(); avg > 0 {
				guardComp["guard_latency_ms"] = math.Round(avg*100) / 100
			}
		}
	}

	droppedHealth := map[string]interface{}{
		"status": "healthy",
		"duckdb": duckDrops,
		"broker": brokerDrops,
		"jsonl":  jsonlDrops,
		"total":  totalDrops,
	}
	if totalDrops > 0 {
		droppedHealth["status"] = "degraded"
	}

	overallStatus := "healthy"
	httpCode := http.StatusOK
	if draining {
		overallStatus = "draining"
		httpCode = http.StatusServiceUnavailable
	} else if !duckOK || totalDrops > 0 {
		overallStatus = "degraded"
		httpCode = http.StatusServiceUnavailable
	}

	writeJSON(w, httpCode, map[string]interface{}{
		"status":   overallStatus,
		"draining": draining,
		"components": map[string]interface{}{
			"duckdb":         duckHealth,
			"jsonl_writer":   map[string]interface{}{"status": jsonlStatus, "dropped": jsonlDrops},
			"event_broker":   map[string]interface{}{"status": brokerStatus, "dropped": brokerDrops},
			"dropped_events": droppedHealth,
			"guard":          guardComp,
		},
	})
}

const readyzPingCacheTTL = 2 * time.Second

func (a *AdminServer) checkDuckDBHealth(ctx context.Context, cfg *config.Config) (map[string]interface{}, bool) {
	if cfg != nil && !cfg.IsTelemetryEnabled() {
		return map[string]interface{}{"status": "disabled"}, true
	}

	if a.telemetryEngine == nil {
		if cfg != nil && cfg.Telemetry.Enabled != nil && *cfg.Telemetry.Enabled {
			return map[string]interface{}{"status": "unhealthy", "error": "telemetry engine not initialized"}, false
		}
		return map[string]interface{}{"status": "disabled"}, true
	}

	provider, ok := a.telemetryEngine.(telemetryDBProvider)
	if !ok {
		return map[string]interface{}{"status": "healthy"}, true
	}
	db := provider.DB()
	if db == nil {
		return map[string]interface{}{"status": "unhealthy", "error": "database connection closed"}, false
	}

	now := time.Now()
	a.dbPingMu.Lock()
	if !a.dbPingAt.IsZero() && now.Sub(a.dbPingAt) < readyzPingCacheTTL {
		err := a.dbPingErr
		a.dbPingMu.Unlock()
		if err != nil {
			return map[string]interface{}{"status": "unhealthy", "error": err.Error()}, false
		}
		return map[string]interface{}{"status": "healthy"}, true
	}
	a.dbPingMu.Unlock()

	pingCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	err := db.PingContext(pingCtx)

	a.dbPingMu.Lock()
	a.dbPingAt = time.Now()
	a.dbPingErr = err
	a.dbPingMu.Unlock()

	if err != nil {
		return map[string]interface{}{"status": "unhealthy", "error": err.Error()}, false
	}
	return map[string]interface{}{"status": "healthy"}, true
}

func (a *AdminServer) collectDroppedEvents() (duckDrops, brokerDrops, jsonlDrops uint64) {
	if dc, ok := a.telemetryEngine.(droppedEventsCounter); ok && dc != nil {
		duckDrops = dc.DroppedEvents()
	}
	if a.eventBroker != nil {
		brokerDrops = a.eventBroker.DroppedCount()
	}
	if a.auditLogDroppedFn != nil {
		jsonlDrops = a.auditLogDroppedFn()
	}
	return duckDrops, brokerDrops, jsonlDrops
}

func (a *AdminServer) handleSecurityAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := q.Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	since, err := parseOptionalRFC3339(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TIME_RANGE", "invalid since timestamp: "+err.Error())
		return
	}
	until, err := parseOptionalRFC3339(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TIME_RANGE", "invalid until timestamp: "+err.Error())
		return
	}

	secReader, ok := a.telemetryEngine.(TelemetrySecurityReader)
	if !ok || secReader == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"total":   0,
			"limit":   limit,
			"offset":  offset,
			"events":  []interface{}{},
		})
		return
	}

	res, err := secReader.QuerySecurityAuditLogs(r.Context(), duckdb.SecurityQueryFilter{
		Limit:     limit,
		Offset:    offset,
		EventType: strings.TrimSpace(q.Get("event_type")),
		ActorID:   strings.TrimSpace(q.Get("actor_id")),
		Outcome:   strings.TrimSpace(q.Get("outcome")),
		Since:     since,
		Until:     until,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SECURITY_AUDIT_QUERY_FAILED", "Failed to query security audit logs: "+err.Error())
		return
	}

	events := res.Events
	if events == nil {
		events = []duckdb.SecurityAuditRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"total":   res.Total,
		"limit":   res.Limit,
		"offset":  res.Offset,
		"events":  events,
	})
}

func (a *AdminServer) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	duckDrops, brokerDrops, jsonlDrops := a.collectDroppedEvents()

	var guardLatencyMS float64
	if lr, ok := a.guardManager.(guard.LatencyReporter); ok && lr != nil {
		if avg := lr.AverageLatencyMS(); avg > 0 {
			guardLatencyMS = math.Round(avg*100) / 100
		}
	}

	droppedMap := map[string]uint64{
		"duckdb": duckDrops,
		"broker": brokerDrops,
		"jsonl":  jsonlDrops,
		"total":  duckDrops + brokerDrops + jsonlDrops,
	}

	analyticsReader, ok := a.telemetryEngine.(TelemetryAnalyticsReader)
	if !ok || analyticsReader == nil {
		normWin := "24h"
		if window == "1h" || window == "7d" {
			normWin = window
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled":          false,
			"window":           normWin,
			"total_calls":      0,
			"allowed_count":    0,
			"blocked_count":    0,
			"masked_count":     0,
			"audit_count":      0,
			"error_count":      0,
			"block_rate":       0,
			"p50_latency_ms":   0,
			"p95_latency_ms":   0,
			"p99_latency_ms":   0,
			"top_rules":        []interface{}{},
			"top_tools":        []interface{}{},
			"dropped_events":   droppedMap,
			"guard_latency_ms": guardLatencyMS,
		})
		return
	}

	summary, err := analyticsReader.GetAnalyticsSummary(r.Context(), window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ANALYTICS_QUERY_FAILED", "Failed to compute analytics summary: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":          true,
		"window":           summary.Window,
		"generated_at":     summary.GeneratedAt,
		"total_calls":      summary.TotalCalls,
		"allowed_count":    summary.AllowedCount,
		"blocked_count":    summary.BlockedCount,
		"masked_count":     summary.MaskedCount,
		"audit_count":      summary.AuditCount,
		"error_count":      summary.ErrorCount,
		"block_rate":       summary.BlockRate,
		"p50_latency_ms":   summary.P50LatencyMS,
		"p95_latency_ms":   summary.P95LatencyMS,
		"p99_latency_ms":   summary.P99LatencyMS,
		"top_rules":        summary.TopRules,
		"top_tools":        summary.TopTools,
		"dropped_events":   droppedMap,
		"guard_latency_ms": guardLatencyMS,
	})
}
