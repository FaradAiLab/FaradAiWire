package admin

import (
	"bufio"
	"cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

func (a *AdminServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	// 1. DuckDB Telemetry Engine: serve filtered, paginated query results (TICK-CORE-002)
	engine := a.telemetryEngine

	if engine != nil {
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}

		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		}

		filter := duckdb.QueryFilter{
			Limit:       limit,
			Offset:      offset,
			Decision:    strings.TrimSpace(r.URL.Query().Get("decision")),
			AgentName:   strings.TrimSpace(r.URL.Query().Get("agent_name")),
			ToolName:    strings.TrimSpace(r.URL.Query().Get("tool_name")),
			TraceID:     strings.TrimSpace(r.URL.Query().Get("trace_id")),
			SummaryOnly: r.URL.Query().Get("summary") == "1",
		}

		result, err := engine.QueryAuditLogs(r.Context(), filter)
		if err != nil {
			slog.ErrorContext(r.Context(), "Failed to query telemetry audit logs", slog.String("error", err.Error()))
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"enabled": true,
				"error":   "Failed to query audit logs",
				"logs":    []interface{}{},
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": true,
			"total":   result.Total,
			"limit":   result.Limit,
			"offset":  result.Offset,
			"logs":    result.Logs,
			"events":  result.Logs,
		})
		return
	}

	// 2. Fallback to legacy file-based JSONL audit trail if configured
	cfg := a.Config()
	if cfg == nil || cfg.AuditLog.Path == "" || !cfg.AuditLog.Enabled {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"logs":    []string{},
		})
		return
	}
	auditLogPath := cfg.AuditLog.Path
	segments, segErr := logger.ListAuditSegmentsDesc(auditLogPath)
	if segErr != nil || len(segments) == 0 {
		slog.WarnContext(r.Context(), "Failed to open fallback audit log file", slog.String("path", auditLogPath))
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": true,
			"error":   "Failed to open audit log file",
			"logs":    []string{},
		})
		return
	}

	const maxFallbackEntries = 100
	const fallbackScannerMaxBytes = 2 * 1024 * 1024 // 2 MB > 1 MB minimum

	var parsedLogs []interface{}
	for _, segPath := range segments {
		if len(parsedLogs) >= maxFallbackEntries {
			break
		}
		file, err := os.Open(segPath)
		if err != nil {
			slog.WarnContext(r.Context(), "Failed to open fallback audit log segment", slog.String("path", segPath), slog.String("error", err.Error()))
			continue
		}

		var segLines []string
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), fallbackScannerMaxBytes)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text == "" {
				continue
			}
			segLines = append(segLines, text)
		}
		if sErr := scanner.Err(); sErr != nil {
			slog.WarnContext(r.Context(), "Fallback audit log scanner warning", slog.String("path", segPath), slog.String("error", sErr.Error()))
		}
		_ = file.Close()

		for i := len(segLines) - 1; i >= 0 && len(parsedLogs) < maxFallbackEntries; i-- {
			line := segLines[i]
			var meta struct {
				RecordType string `json:"record_type"`
				Type       string `json:"type"`
			}
			if json.Unmarshal([]byte(line), &meta) == nil {
				if meta.RecordType == "segment_header" || meta.Type == "segment_header" || meta.RecordType == "security_audit" {
					continue
				}
			}
			var obj interface{}
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
				parsedLogs = append(parsedLogs, obj)
			} else {
				parsedLogs = append(parsedLogs, line)
			}
		}
	}

	if parsedLogs == nil {
		parsedLogs = []interface{}{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"logs":    parsedLogs,
		"events":  parsedLogs,
	})
}

func (a *AdminServer) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	id := cmp.Or(strings.TrimSpace(r.PathValue("id")), strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/audit-logs/")))
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid audit log identifier")
		return
	}

	engine := a.telemetryEngine
	if engine == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "DuckDB telemetry engine not available")
		return
	}

	detailReader, ok := engine.(TelemetryDetailReader)
	if !ok {
		res, err := engine.QueryAuditLogs(r.Context(), duckdb.QueryFilter{TraceID: id, Limit: 1})
		if err != nil || res == nil || len(res.Logs) == 0 {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit record not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"record": res.Logs[0],
		})
		return
	}

	rec, err := detailReader.GetAuditLogByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit record not found")
			return
		}
		slog.ErrorContext(r.Context(), "Failed to retrieve audit record detail", slog.String("id", id), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve audit record")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"record": rec,
	})
}

func (a *AdminServer) handleLogEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported by response writer", http.StatusInternalServerError)
		return
	}

	broker := a.eventBroker
	if broker == nil {
		http.Error(w, "Event streaming service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Set standard SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	eventCh, unsubscribe := broker.Subscribe()
	defer unsubscribe()

	// Initial handshake event
	readyData, _ := json.Marshal(map[string]interface{}{
		"status":      "connected",
		"timestamp":   time.Now().UnixMilli(),
		"subscribers": broker.SubscriberCount(),
	})
	fmt.Fprintf(w, "event: ready\ndata: %s\n\n", readyData)
	flusher.Flush()

	// Keep-alive heartbeat ticker every 15s to keep connections alive through proxies
	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAliveTicker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case batch, ok := <-eventCh:
			if !ok {
				return
			}
			if len(batch) == 0 {
				continue
			}
			data, err := json.Marshal(batch)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: audit_batch\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}
