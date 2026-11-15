package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

func (a *AdminServer) getProtocolsDir() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getProtocolsDirLocked()
}

func (a *AdminServer) getProtocolsDirLocked() string {
	if a.cfg != nil && a.cfg.ProtocolsDir != "" {
		return a.cfg.ProtocolsDir
	}
	return (&config.Config{}).GetProtocolsDir()
}

func (a *AdminServer) getProtocolStore() protocol.Store {
	a.mu.RLock()
	store := a.protocolStore
	a.mu.RUnlock()
	if store != nil {
		return store
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.protocolStore != nil {
		return a.protocolStore
	}

	protocolsDir := a.getProtocolsDirLocked()
	newStore, err := protocol.NewFSStore(protocolsDir)
	if err != nil {
		slog.Error("failed to initialize protocol store", "dir", protocolsDir, "error", err)
		return nil
	}
	a.protocolStore = newStore

	// Connect referential integrity callback to agent repository
	newStore.SetAgentUsageChecker(func(protocolID string) ([]string, error) {
		repo := a.getAgentRepository()
		if repo == nil {
			return nil, nil
		}
		agentNames, err := repo.ListAgents()
		if err != nil {
			return nil, err
		}
		var inUse []string
		for _, name := range agentNames {
			if name == "archive" || name == "agents" || name == "temp" {
				continue
			}
			cfg, err := repo.GetAgentConfig(name)
			if err != nil || cfg == nil {
				continue
			}
			for _, p := range cfg.Protocols {
				if strings.EqualFold(p.ID, protocolID) || strings.EqualFold(p.Name, protocolID) {
					inUse = append(inUse, name)
					break
				}
			}
		}
		return inUse, nil
	})

	if protocolsDir == "./protocols" || protocolsDir == "protocols" {
		_ = newStore.EnsureGitIgnore(".")
	} else if cleanWireDir := filepath.Clean(config.DefaultFaradAiWireDir()); filepath.Clean(protocolsDir) == filepath.Join(cleanWireDir, "protocols") {
		_ = newStore.EnsureGitIgnore(cleanWireDir)
	}
	a.protocolStore = newStore
	return a.protocolStore
}

// handleProtocolPresets returns the curated Top 20 industry-standard MCP presets.
// Endpoint: GET /admin/protocols/presets
func (a *AdminServer) handleProtocolPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET method is supported for presets",
		})
		return
	}

	presets := protocol.GetPresetsCatalog()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presets": presets,
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
	if req.AuthToken == "" || strings.Contains(req.AuthToken, "••••••") {
		req.AuthToken = existing.AuthToken
	}
	if len(req.Headers) == 0 {
		req.Headers = existing.Headers
		return
	}
	for k, v := range req.Headers {
		if strings.Contains(v, "••••••") {
			if orig, ok := existing.Headers[k]; ok {
				req.Headers[k] = orig
			}
		}
	}
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
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for protocol probe",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req ProbeProtocolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "BAD_REQUEST",
			"message": "Invalid request body: " + err.Error(),
		})
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
		if strings.TrimSpace(req.Command) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Command is required for stdio protocol probe",
			})
			return
		}
	case "sse", "http":
		if strings.TrimSpace(req.URL) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "URL is required for SSE protocol probe",
			})
			return
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "BAD_REQUEST",
			"message": fmt.Sprintf("Unsupported protocol type '%s'. Must be 'stdio' or 'sse'", req.Type),
		})
		return
	}

	wantsStream := r.URL.Query().Get("stream") == "1" ||
		strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	runProbe := func(onProgress func(string)) ([]map[string]interface{}, string, error) {
		switch reqType {
		case "stdio":
			tools, err := ProbeAndDiscoverMCPToolsStdioWithProgress(ctx, req.Command, req.Args, req.Env, onProgress)
			return tools, "stdio", err
		default: // "sse", "http"
			ssrfOpts := transport.DefaultSafeOptions()
			a.mu.RLock()
			cfg := a.cfg
			a.mu.RUnlock()
			if cfg != nil {
				ssrfOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
			}
			result, err := ProbeWithAutoNegotiation(ctx, a.SafeHTTPClient(), req.URL, req.AuthToken, req.Headers, ssrfOpts)
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

	w.Header().Set("Content-Type", "application/json")
	if probeErr != nil {
		status, respPayload := buildProbeErrorPayload(probeErr)
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(respPayload)
		return
	}

	if tools == nil {
		tools = make([]map[string]interface{}, 0)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
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

	var upstreamErr *UpstreamHTTPError
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

// handleProtocols manages CRUD operations for MCP protocol definitions.
// Endpoints:
//
//	GET    /admin/protocols         -> List all protocols (masked)
//	GET    /admin/protocols/{id}    -> Get single protocol (masked)
//	POST   /admin/protocols         -> Create new protocol definition
//	PUT    /admin/protocols/{id}    -> Update protocol definition
//	DELETE /admin/protocols/{id}    -> Delete protocol definition (blocked if in use)
func (a *AdminServer) handleProtocols(w http.ResponseWriter, r *http.Request) {
	relPath := strings.TrimPrefix(r.URL.Path, "/admin/protocols")
	relPath = strings.Trim(relPath, "/")

	if relPath == "presets" {
		a.handleProtocolPresets(w, r)
		return
	}
	if relPath == "probe" {
		a.handleProtocolProbe(w, r)
		return
	}

	store := a.getProtocolStore()
	if store == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "STORE_UNAVAILABLE",
			"message": "Protocol store is not initialized",
		})
		return
	}

	// Enforce mutation guard in managed mode for non-GET methods
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
		a.mu.RLock()
		isManaged := a.cfg != nil && a.cfg.IsManaged()
		a.mu.RUnlock()
		if isManaged {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Protocol configuration is locked: Gateway is managed by organization.",
			})
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if relPath == "" {
			protocols, err := store.List()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "LIST_FAILED",
					"message": err.Error(),
				})
				return
			}
			masked := make([]*protocol.Protocol, 0, len(protocols))
			for _, p := range protocols {
				masked = append(masked, p.MaskSecrets())
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"protocols": masked,
			})
			return
		}

		if err := pathguard.ValidateSafeIdentifier(relPath); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_ID",
				"message": "Invalid protocol ID: " + err.Error(),
			})
			return
		}

		p, err := store.Get(relPath)
		if err != nil {
			if errors.Is(err, protocol.ErrProtocolNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": "Protocol not found",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "GET_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(p.MaskSecrets())
		return

	case http.MethodPost:
		w.Header().Set("Content-Type", "application/json")
		if relPath != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Protocol creation should be requested on /admin/protocols without an ID path",
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		var p protocol.Protocol
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Invalid request body: " + err.Error(),
			})
			return
		}

		if err := p.Validate(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "VALIDATION_ERROR",
				"message": err.Error(),
			})
			return
		}

		// Check if protocol already exists
		existing, _ := store.Get(p.ID)
		if existing != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "CONFLICT",
				"message": "Protocol with ID '" + p.ID + "' already exists. Use PUT to update.",
			})
			return
		}

		if err := store.Save(&p); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "SAVE_FAILED",
				"message": err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "created",
			"protocol": p.MaskSecrets(),
		})
		return

	case http.MethodPut:
		w.Header().Set("Content-Type", "application/json")
		if relPath == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Protocol ID is required in URL path for PUT",
			})
			return
		}

		if err := pathguard.ValidateSafeIdentifier(relPath); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_ID",
				"message": "Invalid protocol ID: " + err.Error(),
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var p protocol.Protocol
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Invalid request body: " + err.Error(),
			})
			return
		}

		p.ID = relPath
		if err := p.Validate(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "VALIDATION_ERROR",
				"message": err.Error(),
			})
			return
		}

		// Preserve CreatedAt and existing secrets if client sent masked value back
		if existing, err := store.Get(relPath); err == nil && existing != nil {
			p.CreatedAt = existing.CreatedAt

			existingEnvMap := make(map[string]string)
			for _, e := range existing.Env {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 {
					existingEnvMap[parts[0]] = parts[1]
				}
			}
			for i, e := range p.Env {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 && strings.Contains(parts[1], "••••••") {
					if origVal, exists := existingEnvMap[parts[0]]; exists {
						p.Env[i] = parts[0] + "=" + origVal
					}
				}
			}

			// Preserve AuthToken if client sent masked placeholder back
			if strings.Contains(p.AuthToken, "••••••") {
				p.AuthToken = existing.AuthToken
			}

			// Preserve sensitive Headers if client sent masked placeholder back
			if p.Headers != nil && existing.Headers != nil {
				for k, v := range p.Headers {
					if strings.Contains(v, "••••••") {
						if origVal, exists := existing.Headers[k]; exists {
							p.Headers[k] = origVal
						}
					}
				}
			}
		}

		if err := store.Save(&p); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "SAVE_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "updated",
			"protocol": p.MaskSecrets(),
		})
		return

	case http.MethodDelete:
		w.Header().Set("Content-Type", "application/json")
		protocolID := relPath
		if protocolID == "" {
			protocolID = r.URL.Query().Get("id")
		}
		if protocolID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Protocol ID is required",
			})
			return
		}

		if err := store.Delete(protocolID); err != nil {
			if errors.Is(err, protocol.ErrProtocolNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": "Protocol not found",
				})
				return
			}
			if errors.Is(err, protocol.ErrProtocolInUse) {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "PROTOCOL_IN_USE",
					"message": err.Error(),
				})
				return
			}
			if errors.Is(err, protocol.ErrInvalidID) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "INVALID_ID",
					"message": err.Error(),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "DELETE_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "Protocol successfully deleted",
		})
		return

	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Method not allowed",
		})
	}
}
