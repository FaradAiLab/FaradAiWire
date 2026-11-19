package admin

import (
	"bufio"
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

	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

func (a *AdminServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 1. DuckDB Telemetry Engine: serve filtered, paginated query results (TICK-CORE-002)
	a.mu.RLock()
	engine := a.telemetryEngine
	a.mu.RUnlock()

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
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"enabled": true,
				"error":   "Failed to query audit logs",
				"logs":    []interface{}{},
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
			"logs":    []string{},
		})
		return
	}
	auditLogPath := cfg.AuditLog.Path

	file, err := os.Open(auditLogPath)
	if err != nil {
		slog.WarnContext(r.Context(), "Failed to open fallback audit log file", slog.String("error", err.Error()))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": true,
			"error":   "Failed to open audit log file",
			"logs":    []string{},
		})
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 100 {
			lines = lines[1:]
		}
	}

	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	var parsedLogs []interface{}
	for _, l := range lines {
		var obj interface{}
		if err := json.Unmarshal([]byte(l), &obj); err == nil {
			parsedLogs = append(parsedLogs, obj)
		} else {
			parsedLogs = append(parsedLogs, l)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": true,
		"logs":    parsedLogs,
		"events":  parsedLogs,
	})
}

func (a *AdminServer) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/audit-logs/"))
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "Invalid audit log identifier", http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	engine := a.telemetryEngine
	a.mu.RUnlock()
	if engine == nil {
		http.Error(w, "DuckDB telemetry engine not available", http.StatusNotFound)
		return
	}

	detailReader, ok := engine.(TelemetryDetailReader)
	if !ok {
		res, err := engine.QueryAuditLogs(r.Context(), duckdb.QueryFilter{TraceID: id, Limit: 1})
		if err != nil || res == nil || len(res.Logs) == 0 {
			http.Error(w, "Audit record not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"record": res.Logs[0],
		})
		return
	}

	rec, err := detailReader.GetAuditLogByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Audit record not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "Failed to retrieve audit record detail", slog.String("id", id), slog.String("error", err.Error()))
		http.Error(w, "Failed to retrieve audit record", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

	a.mu.RLock()
	broker := a.eventBroker
	a.mu.RUnlock()

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
