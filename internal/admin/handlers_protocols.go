package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

func (a *AdminServer) getProtocolsDir() string {
	if a.cfg != nil && a.cfg.ProtocolsDir != "" {
		return a.cfg.ProtocolsDir
	}
	return "./protocols"
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

	newStore, err := protocol.NewFSStore(a.getProtocolsDir())
	if err != nil {
		slog.Error("failed to initialize protocol store", "dir", a.getProtocolsDir(), "error", err)
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

	_ = newStore.EnsureGitIgnore(".")
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
	existing := matchStoredProtocol(store, req.ID, req.URL, req.Command)
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

func matchStoredProtocol(store protocol.Store, id, targetURL, cmd string) *protocol.Protocol {
	if id != "" {
		if p, err := store.Get(id); err == nil && p != nil {
			return p
		}
	}
	all, _ := store.List()
	for _, p := range all {
		if targetURL != "" && (p.URLOrCommand == targetURL || p.Command == targetURL) {
			return p
		}
		if cmd != "" && p.Command == cmd {
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

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var tools []map[string]interface{}
	var probeErr error
	var transportMode string

	reqType := strings.ToLower(strings.TrimSpace(req.Type))
	if reqType == "" {
		if req.URL != "" {
			reqType = "sse"
		} else if req.Command != "" {
			reqType = "stdio"
		}
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
		tools, probeErr = ProbeAndDiscoverMCPToolsStdio(ctx, req.Command, req.Args, req.Env)
		transportMode = "stdio"

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
		ssrfOpts := transport.DefaultSafeOptions()
		if a.cfg != nil {
			ssrfOpts = transport.OptionsFromConfig(a.cfg.Security.SSRFProtection)
		}
		result, err := ProbeWithAutoNegotiation(ctx, a.SafeHTTPClient(), req.URL, req.AuthToken, req.Headers, ssrfOpts)
		if err != nil {
			probeErr = err
		} else {
			tools = result.Tools
			transportMode = result.TransportMode
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

	w.Header().Set("Content-Type", "application/json")
	if probeErr != nil {
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

// handleProtocols manages CRUD operations for MCP protocol definitions.
// Endpoints:
//   GET    /admin/protocols         -> List all protocols (masked)
//   GET    /admin/protocols/{id}    -> Get single protocol (masked)
//   POST   /admin/protocols         -> Create new protocol definition
//   PUT    /admin/protocols/{id}    -> Update protocol definition
//   DELETE /admin/protocols/{id}    -> Delete protocol definition (blocked if in use)
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
		if a.cfg != nil && a.cfg.IsManaged() {
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
