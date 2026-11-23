package admin

import (
	"bufio"
	"cmp"
	"database/sql"
	"encoding/csv"
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

func parseOptionalRFC3339(raw string) (*time.Time, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, err
	}
	utc := parsed.UTC()
	return &utc, nil
}

func parseAuditQueryFilter(r *http.Request) (duckdb.QueryFilter, error) {
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
		return duckdb.QueryFilter{}, fmt.Errorf("invalid since timestamp: %w", err)
	}
	until, err := parseOptionalRFC3339(q.Get("until"))
	if err != nil {
		return duckdb.QueryFilter{}, fmt.Errorf("invalid until timestamp: %w", err)
	}
	return duckdb.QueryFilter{
		Limit:       limit,
		Offset:      offset,
		Decision:    strings.TrimSpace(q.Get("decision")),
		AgentName:   strings.TrimSpace(q.Get("agent_name")),
		ToolName:    strings.TrimSpace(q.Get("tool_name")),
		TraceID:     strings.TrimSpace(q.Get("trace_id")),
		MatchedRule: strings.TrimSpace(q.Get("matched_rule")),
		Search:      strings.TrimSpace(q.Get("q")),
		SummaryOnly: q.Get("summary") == "1",
		Since:       since,
		Until:       until,
	}, nil
}

func (a *AdminServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	// 1. DuckDB Telemetry Engine: serve filtered, paginated query results (TICK-CORE-002)
	engine := a.telemetryEngine

	if engine != nil {
		filter, err := parseAuditQueryFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_TIME_RANGE", err.Error())
			return
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

func (a *AdminServer) exportMaxRows() int {
	maxRows := 50000
	if cache := a.getSettingsCache(); cache != nil {
		if s := cache.Get(); s != nil && s.Maintenance.AuditExportMaxRows > 0 {
			maxRows = s.Maintenance.AuditExportMaxRows
		}
	}
	return maxRows
}

func sanitizeAuditRecordForExport(rec duckdb.AuditRecord) duckdb.AuditRecord {
	// ZERO-DLP BLEED: Never export raw unmasked local-vault payload snapshots.
	rec.OriginalPayloadPreview = ""
	rec.OriginalRequest = ""
	rec.OriginalResponse = ""

	if strings.EqualFold(rec.Decision, "BLOCKED") ||
		strings.EqualFold(rec.Decision, "CRITICAL") ||
		strings.EqualFold(rec.RequestDecision, "BLOCKED") ||
		strings.EqualFold(rec.ResponseDecision, "BLOCKED") {
		rec.Request = ""
		rec.Response = ""
		if !strings.HasPrefix(rec.RawPayloadPreview, "[REDACTED") {
			rec.RawPayloadPreview = fmt.Sprintf("[REDACTED - Blocked by %s]", cmp.Or(rec.MatchedRule, "policy"))
		}
	}
	return rec
}

func sanitizeCSVCell(v string) string {
	if len(v) == 0 {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	default:
		return v
	}
}

var csvExportHeader = []string{
	"id",
	"timestamp",
	"trace_id",
	"agent_name",
	"tool_name",
	"caller_role",
	"user_id",
	"client_ip",
	"api_key_id",
	"path_type",
	"decision",
	"request_decision",
	"response_decision",
	"matched_rule",
	"error_code",
	"human_approved",
	"approved_by",
	"approval_channel",
	"error_message",
	"latency_ms",
	"input_size_bytes",
	"output_size_bytes",
	"raw_payload_preview",
	"request",
	"response",
	"hash_version",
	"integrity_hash",
}

func formatAuditRecordCSVRow(rec duckdb.AuditRecord) []string {
	raw := []string{
		rec.ID,
		rec.Timestamp.UTC().Format(time.RFC3339Nano),
		rec.TraceID,
		rec.AgentName,
		rec.ToolName,
		rec.CallerRole,
		rec.UserID,
		rec.ClientIP,
		rec.APIKeyID,
		rec.PathType,
		rec.Decision,
		rec.RequestDecision,
		rec.ResponseDecision,
		rec.MatchedRule,
		strconv.Itoa(rec.ErrorCode),
		strconv.FormatBool(rec.HumanApproved),
		rec.ApprovedBy,
		rec.ApprovalChannel,
		rec.ErrorMessage,
		strconv.FormatFloat(rec.LatencyMs, 'f', 3, 64),
		strconv.Itoa(rec.InputSizeBytes),
		strconv.Itoa(rec.OutputSizeBytes),
		rec.RawPayloadPreview,
		rec.Request,
		rec.Response,
		rec.HashVersion,
		rec.IntegrityHash,
	}
	for i := range raw {
		raw[i] = sanitizeCSVCell(raw[i])
	}
	return raw
}

func (a *AdminServer) handleAuditLogsExport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "csv" {
		writeError(w, http.StatusBadRequest, "INVALID_EXPORT_FORMAT", "Unsupported export format; expected 'jsonl' or 'csv'")
		return
	}

	filter, err := parseAuditQueryFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TIME_RANGE", err.Error())
		return
	}

	maxRows := a.exportMaxRows()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="faradaiwire-audit.csv"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="faradaiwire-audit.jsonl"`)
	}
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	var csvWriter *csv.Writer
	if format == "csv" {
		csvWriter = csv.NewWriter(w)
		_ = csvWriter.Write(csvExportHeader)
		csvWriter.Flush()
	}

	engine := a.telemetryEngine
	if engine == nil {
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	const chunkSize = 500
	offset := 0
	exported := 0

	for exported < maxRows {
		remaining := maxRows - exported
		pageLimit := chunkSize
		if remaining < pageLimit {
			pageLimit = remaining
		}
		pageFilter := filter
		pageFilter.Limit = pageLimit
		pageFilter.Offset = offset
		pageFilter.SummaryOnly = false

		res, qErr := engine.QueryAuditLogs(r.Context(), pageFilter)
		if qErr != nil || res == nil || len(res.Logs) == 0 {
			break
		}

		for _, rawRec := range res.Logs {
			safeRec := sanitizeAuditRecordForExport(rawRec)
			if format == "csv" {
				_ = csvWriter.Write(formatAuditRecordCSVRow(safeRec))
			} else {
				line, mErr := json.Marshal(safeRec)
				if mErr != nil {
					continue
				}
				_, _ = w.Write(line)
				_, _ = w.Write([]byte{'\n'})
			}
			exported++
			if exported >= maxRows {
				break
			}
		}

		if csvWriter != nil {
			csvWriter.Flush()
		}
		if flusher != nil {
			flusher.Flush()
		}
		if len(res.Logs) < pageLimit {
			break
		}
		offset += len(res.Logs)
	}
}
