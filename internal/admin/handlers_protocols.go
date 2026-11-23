package admin

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpprobe"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

const stdioDisabledMsg = "Local stdio subprocess execution is disabled when allow_stdio is false. Use Remote SSE or Streamable HTTP."

func (a *AdminServer) isStdioAllowed() bool {
	if cfg := a.Config(); cfg != nil {
		return cfg.IsStdioAllowed()
	}
	return (&config.Config{}).IsStdioAllowed()
}

func (a *AdminServer) getProtocolStore() protocol.Store {
	return a.protocolStore
}

// handleProtocolPresets returns the curated Top 20 industry-standard MCP presets (GET /admin/protocols/presets).
// Returns an empty slice when allow_stdio is false (Containerized Security Gateway mode).
func (a *AdminServer) handleProtocolPresets(w http.ResponseWriter, r *http.Request) {
	if !a.isStdioAllowed() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"presets": []protocol.PresetMetadata{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"presets": protocol.GetPresetsCatalog(),
	})
}

// ProbeProtocolRequest contains parameters for active MCP connection testing and tool discovery.
type ProbeProtocolRequest struct {
	ID        string            `json:"id,omitempty"`
	Type      string            `json:"type"` // "stdio", "sse", "http"
	URL       string            `json:"url,omitempty"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       []string          `json:"env,omitempty"`
	AuthToken string            `json:"auth_token,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

func hydrateProbeSecrets(req *ProbeProtocolRequest, store protocol.Store) {
	if store == nil {
		return
	}
	existing := matchStoredProtocol(store, req)
	if existing == nil {
		return
	}
	req.AuthToken = protocol.PreserveMaskedSecret(req.AuthToken, existing.AuthToken, true)
	req.Headers = protocol.MergeMaskedHeaders(req.Headers, existing.Headers, true)
}

func probeMatchesStoredDestination(req *ProbeProtocolRequest, p *protocol.Protocol) bool {
	if req == nil || p == nil {
		return false
	}
	reqType := strings.ToLower(strings.TrimSpace(req.Type))
	if reqType == "stdio" || (reqType == "" && strings.TrimSpace(req.Command) != "") {
		if !strings.EqualFold(p.Type, "stdio") && p.Command == "" {
			return false
		}
		return strings.TrimSpace(req.Command) == strings.TrimSpace(p.Command) && slices.Equal(req.Args, p.Args)
	}
	reqURL := strings.TrimSpace(req.URL)
	storedURL := strings.TrimSpace(p.URLOrCommand)
	return reqURL != "" && storedURL != "" && reqURL == storedURL
}

func matchStoredProtocol(store protocol.Store, req *ProbeProtocolRequest) *protocol.Protocol {
	if req == nil {
		return nil
	}
	if req.ID != "" {
		if p, err := store.Get(req.ID); err == nil && p != nil {
			// Prevent secret exfiltration by requiring the probe destination to match the stored protocol target.
			if probeMatchesStoredDestination(req, p) {
				return p
			}
			return nil
		}
	}
	targetURL := strings.TrimSpace(req.URL)
	cmd := strings.TrimSpace(req.Command)
	all, _ := store.List()
	for _, p := range all {
		if targetURL != "" && (p.URLOrCommand == targetURL || p.Command == targetURL) {
			return p
		}
		if cmd != "" && p.Command == cmd && slices.Equal(req.Args, p.Args) {
			return p
		}
	}
	return nil
}

// handleProtocolProbe executes an active SSRF-safe connection test and tool discovery against an MCP endpoint.
// Endpoint: POST /admin/protocols/probe
func (a *AdminServer) handleProtocolProbe(w http.ResponseWriter, r *http.Request) {
	var req ProbeProtocolRequest
	if err := decodeJSON(w, r, maxAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	hydrateProbeSecrets(&req, a.getProtocolStore())

	reqType := strings.ToLower(strings.TrimSpace(req.Type))
	if reqType == "" {
		if req.URL != "" {
			reqType = "sse"
		} else if req.Command != "" {
			reqType = "stdio"
		}
	}

	probeTimeout := a.probeTimeout()
	if reqType == "stdio" {
		probeTimeout = a.stdioProbeTimeout(req.Command)
	}

	switch reqType {
	case "stdio":
		if !a.isStdioAllowed() {
			writeError(w, http.StatusBadRequest, "STDIO_DISABLED", stdioDisabledMsg)
			return
		}
		if strings.TrimSpace(req.Command) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Command is required for stdio protocol probe")
			return
		}
	case "sse", "http":
		if strings.TrimSpace(req.URL) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "URL is required for SSE protocol probe")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("Unsupported protocol type '%s'. Must be 'stdio' or 'sse'", req.Type))
		return
	}

	wantsStream := r.URL.Query().Get("stream") == "1" ||
		strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	runProbe := func(onProgress func(string)) ([]map[string]interface{}, string, error) {
		switch reqType {
		case "stdio":
			tools, err := mcpprobe.ProbeStdio(ctx, mcpprobe.StdioProbeRequest{
				Command:    req.Command,
				Args:       req.Args,
				Env:        req.Env,
				OnProgress: onProgress,
			})
			return tools, "stdio", err
		default: // "sse", "http"
			ssrfOpts := transport.DefaultSafeOptions()
			if cfg := a.Config(); cfg != nil {
				ssrfOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
			}
			result, err := mcpprobe.ProbeHTTP(ctx, mcpprobe.ProbeRequest{
				Client:        a.SafeHTTPClient(),
				TargetURL:     req.URL,
				AuthToken:     req.AuthToken,
				CustomHeaders: req.Headers,
				SSRFOptions:   ssrfOpts,
			})
			if err != nil {
				return nil, "", err
			}
			return result.Tools, result.TransportMode, nil
		}
	}

	if wantsStream {
		streamProtocolProbe(w, r, ctx, reqType, req.Command, probeTimeout, runProbe)
		return
	}

	tools, transportMode, probeErr := runProbe(nil)
	if probeErr != nil {
		status, respPayload := buildProbeErrorPayload(probeErr)
		writeJSON(w, status, respPayload)
		return
	}

	if tools == nil {
		tools = make([]map[string]interface{}, 0)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "success",
		"count":          len(tools),
		"tools":          tools,
		"transport_mode": transportMode,
	})
}

func streamProtocolProbe(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
	reqType string,
	command string,
	probeTimeout time.Duration,
	runProbe func(onProgress func(string)) ([]map[string]interface{}, string, error),
) {
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	startedAt := time.Now()
	timeoutSec := int(probeTimeout.Seconds())
	initialMsg := fmt.Sprintf("Connecting to %s endpoint...", reqType)
	if reqType == "stdio" {
		initialMsg = fmt.Sprintf("Starting stdio subprocess '%s'...", command)
	}
	emitProgress := func(msg string) {
		writeProbeSSE(w, flusher, canFlush, "progress", map[string]interface{}{
			"message":     msg,
			"elapsed_ms":  time.Since(startedAt).Milliseconds(),
			"timeout_sec": timeoutSec,
		})
	}
	emitProgress(initialMsg)

	progressCh := make(chan string, 64)
	type probeOutcome struct {
		tools         []map[string]interface{}
		transportMode string
		err           error
	}
	doneCh := make(chan probeOutcome, 1)

	go func() {
		tools, mode, err := runProbe(func(line string) {
			select {
			case progressCh <- line:
			default:
				// Drop excess progress lines rather than blocking the subprocess stderr pipe.
			}
		})
		doneCh <- probeOutcome{tools: tools, transportMode: mode, err: err}
	}()

	drainProgress := func() {
		for {
			select {
			case line := <-progressCh:
				emitProgress(line)
			default:
				return
			}
		}
	}

	var outcome probeOutcome
	for waiting := true; waiting; {
		select {
		case line := <-progressCh:
			emitProgress(line)
		case outcome = <-doneCh:
			waiting = false
		case <-ctx.Done():
			// Wait for runProbe goroutine to unwind and flush pending stderr lines before closing.
			outcome = <-doneCh
			waiting = false
		}
	}

	// Skip writing SSE frames if the HTTP client disconnected/aborted the request.
	if r.Context().Err() != nil {
		return
	}

	drainProgress()

	if outcome.err != nil {
		_, respPayload := buildProbeErrorPayload(outcome.err)
		writeProbeSSE(w, flusher, canFlush, "error", respPayload)
		return
	}

	tools := outcome.tools
	if tools == nil {
		tools = make([]map[string]interface{}, 0)
	}
	writeProbeSSE(w, flusher, canFlush, "result", map[string]interface{}{
		"status":         "success",
		"count":          len(tools),
		"tools":          tools,
		"transport_mode": outcome.transportMode,
	})
}

func buildProbeErrorPayload(probeErr error) (int, map[string]interface{}) {
	status := http.StatusBadGateway
	errCode := "PROBE_FAILED"
	respPayload := map[string]interface{}{
		"message": probeErr.Error(),
	}

	var upstreamErr *mcpprobe.UpstreamHTTPError
	if errors.As(probeErr, &upstreamErr) {
		// Structured upstream HTTP error with actionable diagnostics
		status = http.StatusBadGateway
		errCode = upstreamErr.Category
		respPayload["status_code"] = upstreamErr.StatusCode
		respPayload["remediation"] = upstreamErr.Remediation
	} else if strings.Contains(probeErr.Error(), "SSRF") || strings.Contains(probeErr.Error(), "security violation") {
		status = http.StatusBadRequest
		errCode = "SSRF_VIOLATION"
	}

	respPayload["error"] = errCode
	return status, respPayload
}

func writeProbeSSE(w http.ResponseWriter, flusher http.Flusher, canFlush bool, event string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if canFlush {
		flusher.Flush()
	}
}

func (a *AdminServer) requireProtocolStore(w http.ResponseWriter) protocol.Store {
	store := a.getProtocolStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "Protocol store is not initialized")
		return nil
	}
	return store
}

// handleListProtocols lists all registered protocol definitions with secrets masked (GET /admin/protocols).
func (a *AdminServer) handleListProtocols(w http.ResponseWriter, r *http.Request) {
	store := a.requireProtocolStore(w)
	if store == nil {
		return
	}

	protocols, err := store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LIST_FAILED", err.Error())
		return
	}

	masked := make([]*protocol.Protocol, 0, len(protocols))
	for _, p := range protocols {
		masked = append(masked, p.MaskSecrets())
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"protocols": masked})
}

// handleGetProtocol retrieves a single masked protocol definition (GET /admin/protocols/{id}).
func (a *AdminServer) handleGetProtocol(w http.ResponseWriter, r *http.Request) {
	store := a.requireProtocolStore(w)
	if store == nil {
		return
	}

	protocolID := r.PathValue("id")
	if err := pathguard.ValidateSafeIdentifier(protocolID); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid protocol ID: "+err.Error())
		return
	}

	p, err := store.Get(protocolID)
	if err != nil {
		if errors.Is(err, protocol.ErrProtocolNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Protocol not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, p.MaskSecrets())
}

// handleCreateProtocol validates and persists a new protocol definition (POST /admin/protocols).
func (a *AdminServer) handleCreateProtocol(w http.ResponseWriter, r *http.Request) {
	store := a.requireProtocolStore(w)
	if store == nil {
		return
	}

	var p protocol.Protocol
	if err := decodeJSON(w, r, maxAdminBodyBytes, &p); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	if err := p.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	if strings.EqualFold(p.Type, "stdio") && !a.isStdioAllowed() {
		writeError(w, http.StatusBadRequest, "STDIO_DISABLED", stdioDisabledMsg)
		return
	}
	if existing, _ := store.Get(p.ID); existing != nil {
		writeError(w, http.StatusConflict, "CONFLICT", "Protocol with ID '"+p.ID+"' already exists. Use PUT to update.")
		return
	}
	if err := store.Save(&p); err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}

	a.logSecurityAudit(r, "protocol_mutated", "create", "protocol", p.ID, "allowed", "Protocol created", map[string]any{"type": p.Type})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":   "created",
		"protocol": p.MaskSecrets(),
	})
}

// handleUpdateProtocol updates a protocol definition while preserving masked secrets (PUT /admin/protocols/{id}).
func (a *AdminServer) handleUpdateProtocol(w http.ResponseWriter, r *http.Request) {
	store := a.requireProtocolStore(w)
	if store == nil {
		return
	}

	protocolID := r.PathValue("id")
	if err := pathguard.ValidateSafeIdentifier(protocolID); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid protocol ID: "+err.Error())
		return
	}

	var p protocol.Protocol
	if err := decodeJSON(w, r, maxAdminBodyBytes, &p); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	p.ID = protocolID
	if err := p.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	if strings.EqualFold(p.Type, "stdio") && !a.isStdioAllowed() {
		writeError(w, http.StatusBadRequest, "STDIO_DISABLED", stdioDisabledMsg)
		return
	}

	if existing, err := store.Get(protocolID); err == nil && existing != nil {
		p.CreatedAt = existing.CreatedAt
		p.HydrateMaskedSecrets(existing)
	}

	if err := store.Save(&p); err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}

	a.logSecurityAudit(r, "protocol_mutated", "update", "protocol", protocolID, "allowed", "Protocol updated", map[string]any{"type": p.Type})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "updated",
		"protocol": p.MaskSecrets(),
	})
}

// handleDeleteProtocol deletes an unused protocol definition (DELETE /admin/protocols/{id}).
func (a *AdminServer) handleDeleteProtocol(w http.ResponseWriter, r *http.Request) {
	store := a.requireProtocolStore(w)
	if store == nil {
		return
	}

	protocolID := cmp.Or(r.PathValue("id"), r.URL.Query().Get("id"))
	if protocolID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Protocol ID is required")
		return
	}

	if err := store.Delete(protocolID); err != nil {
		switch {
		case errors.Is(err, protocol.ErrProtocolNotFound):
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Protocol not found")
		case errors.Is(err, protocol.ErrProtocolInUse):
			writeError(w, http.StatusConflict, "PROTOCOL_IN_USE", err.Error())
		case errors.Is(err, protocol.ErrInvalidID):
			writeError(w, http.StatusBadRequest, "INVALID_ID", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "DELETE_FAILED", err.Error())
		}
		return
	}

	a.logSecurityAudit(r, "protocol_mutated", "delete", "protocol", protocolID, "allowed", "Protocol deleted", nil)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Protocol successfully deleted",
	})
}
