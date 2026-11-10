package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

func (a *AdminServer) getAgentsDir() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getAgentsDirLocked()
}

func (a *AdminServer) getAgentsDirLocked() string {
	if a.cfg != nil && a.cfg.AgentsDir != "" {
		return a.cfg.AgentsDir
	}
	agentsDir := "./agents"
	if _, err := os.Stat(agentsDir); os.IsNotExist(err) {
		agentsDir = filepath.Join(config.DefaultFaradAiWireDir(), "agents")
	}
	return agentsDir
}

func (a *AdminServer) getAgentRepository() agent.Repository {
	a.mu.RLock()
	repo := a.agentRepo
	a.mu.RUnlock()
	if repo != nil {
		return repo
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.agentRepo == nil {
		a.agentRepo = agent.NewFSRepository(a.getAgentsDirLocked())
	}
	return a.agentRepo
}

// handleAgents manages full CRUD lifecycle operations for AI agents.
// Endpoints:
//
//	GET    /admin/agents         -> List all agents with tools and status
//	GET    /admin/agents/{name}  -> Get single agent with effective tools
//	POST   /admin/agents         -> Create new agent, probe tools, save manifest
//	PUT    /admin/agents/{name}  -> Update agent config, archive prior snapshot
//	DELETE /admin/agents/{name}  -> Delete agent (blocked if active sessions exist)
func (a *AdminServer) handleAgents(w http.ResponseWriter, r *http.Request) {
	relPath := strings.TrimPrefix(r.URL.Path, "/admin/agents")
	relPath = strings.Trim(relPath, "/")

	if relPath == "archives" || relPath == "sync-tools" || relPath == "rollback" {
		return
	}

	if strings.HasSuffix(relPath, "/dlp") {
		agentName := strings.TrimSuffix(relPath, "/dlp")
		a.handleAgentDLP(w, r, agentName)
		return
	}

	// Managed mode guard for mutations
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
		a.mu.RLock()
		cfg := a.cfg
		a.mu.RUnlock()
		if cfg != nil && cfg.IsManaged() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Agent editing is locked: Gateway is managed by organization.",
			})
			return
		}
	}

	repo := a.getAgentRepository()
	if repo == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "REPO_UNAVAILABLE",
			"message": "Agent repository is not initialized",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if relPath == "" {
			agentNames, err := repo.ListAgents()
			if err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"agents": []interface{}{}})
				return
			}
			sort.Strings(agentNames)

			var agents []map[string]interface{}
			for _, agentName := range agentNames {
				if agentName == "archive" || agentName == "agents" || agentName == "temp" {
					continue
				}
				if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
					continue
				}
				cfg, err := repo.GetAgentConfig(agentName)
				if err != nil {
					continue
				}
				routingMode := "aggregated"
				if cfg.RoutingMode != "" {
					routingMode = cfg.RoutingMode
				}
				tools, _ := repo.GetAgentManifest(agentName)
				effectiveTools := cfg.ComputeEffectiveTools(tools)

				agents = append(agents, map[string]interface{}{
					"name":            agentName,
					"routing_mode":    routingMode,
					"config":          cfg.MaskSecrets(),
					"tools":           tools,
					"effective_tools": effectiveTools,
					"status":          "active",
				})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"agents": agents})
			return
		}

		if err := pathguard.ValidateSafeIdentifier(relPath); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid agent name: " + err.Error(),
			})
			return
		}

		cfg, err := repo.GetAgentConfig(relPath)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Agent '%s' not found", relPath),
			})
			return
		}

		routingMode := "aggregated"
		if cfg.RoutingMode != "" {
			routingMode = cfg.RoutingMode
		}
		tools, _ := repo.GetAgentManifest(relPath)
		effectiveTools := cfg.ComputeEffectiveTools(tools)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":            relPath,
			"routing_mode":    routingMode,
			"config":          cfg.MaskSecrets(),
			"tools":           tools,
			"effective_tools": effectiveTools,
			"status":          "active",
		})
		return

	case http.MethodPost:
		w.Header().Set("Content-Type", "application/json")
		if relPath != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Agent creation should be requested on /admin/agents without a URL path identifier",
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var payload AgentPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Invalid request body: " + err.Error(),
			})
			return
		}

		agentName := strings.TrimSpace(payload.AgentName)
		if agentName == "" {
			agentName = strings.TrimSpace(payload.Name)
		}
		if agentName == "" {
			agentName = strings.TrimSpace(payload.AgentID)
		}
		if agentName == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "agent_name is required",
			})
			return
		}

		if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid agent name: " + err.Error(),
			})
			return
		}

		// Conflict check
		if existing, _ := repo.GetAgentConfig(agentName); existing != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "AGENT_ALREADY_EXISTS",
				"message": fmt.Sprintf("Agent '%s' already exists. Use PUT to update.", agentName),
			})
			return
		}

		if err := validateToolGovernance(payload.ToolGovernance); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_GOVERNANCE_MODE",
				"message": err.Error(),
			})
			return
		}

		if err := validateRetainedGovernance(payload.RetainedGovernance); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_RETAINED_GOVERNANCE_MODE",
				"message": err.Error(),
			})
			return
		}

		if err := validateRateLimit(payload.RateLimit); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_RATE_LIMIT",
				"message": err.Error(),
			})
			return
		}

		if err := validateLoopProtection(payload.LoopProtection); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_LOOP_PROTECTION",
				"message": err.Error(),
			})
			return
		}

		protocols := a.enrichAgentProtocols(payload.Protocols, payload.ProtocolIDs)
		routingMode := strings.ToLower(strings.TrimSpace(payload.RoutingMode))
		if routingMode == "" {
			routingMode = "aggregated"
		}

		cfg := &agent.RouteConfig{
			AgentID:            agentName,
			AgentName:          agentName,
			Description:        payload.Description,
			RoutingMode:        routingMode,
			Protocols:          protocols,
			EnabledTools:       payload.EnabledTools,
			ToolOverrides:      payload.ToolOverrides,
			ToolGovernance:     payload.ToolGovernance,
			RetainedGovernance: payload.RetainedGovernance,
			RateLimit:          payload.RateLimit,
			LoopProtection:     payload.LoopProtection,
		}

		if err := repo.SaveAgentConfig(agentName, cfg); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "SAVE_FAILED",
				"message": err.Error(),
			})
			return
		}

		// Probe attached protocols and persist tools_manifest.json
		discoveredTools, _ := a.syncAgentToolsProbed(r.Context(), agentName, cfg)
		toolsMeta, _ := repo.GetAgentManifest(agentName)
		effectiveTools := cfg.ComputeEffectiveTools(toolsMeta)

		a.mu.RLock()
		reloadFn := a.reloadFunc
		a.mu.RUnlock()
		if reloadFn != nil {
			if err := reloadFn(); err != nil {
				slog.WarnContext(r.Context(), "Failed to reload runtime configuration after agent mutation", slog.String("agent", agentName), slog.String("error", err.Error()))
			}
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "created",
			"agent": map[string]interface{}{
				"name":            agentName,
				"routing_mode":    routingMode,
				"config":          cfg.MaskSecrets(),
				"tools":           discoveredTools,
				"effective_tools": effectiveTools,
				"status":          "active",
			},
		})
		return

	case http.MethodPut:
		w.Header().Set("Content-Type", "application/json")
		if relPath == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Agent name is required in URL path for PUT",
			})
			return
		}

		agentName := relPath
		if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid agent name: " + err.Error(),
			})
			return
		}

		existingCfg, err := repo.GetAgentConfig(agentName)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Agent '%s' not found", agentName),
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var payload AgentPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Invalid request body: " + err.Error(),
			})
			return
		}

		if err := validateToolGovernance(payload.ToolGovernance); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_GOVERNANCE_MODE",
				"message": err.Error(),
			})
			return
		}

		if err := validateRetainedGovernance(payload.RetainedGovernance); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_RETAINED_GOVERNANCE_MODE",
				"message": err.Error(),
			})
			return
		}

		if err := validateRateLimit(payload.RateLimit); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_RATE_LIMIT",
				"message": err.Error(),
			})
			return
		}

		if err := validateLoopProtection(payload.LoopProtection); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_LOOP_PROTECTION",
				"message": err.Error(),
			})
			return
		}

		updatedCfg := existingCfg.Clone()
		if payload.Description != "" {
			updatedCfg.Description = payload.Description
		}
		if payload.RoutingMode != "" {
			updatedCfg.RoutingMode = strings.ToLower(strings.TrimSpace(payload.RoutingMode))
		}
		// Sanitize protocol IDs to eliminate whitespace and empty values (golang-security: input validation)
		var validProtocolIDs []string
		if len(payload.ProtocolIDs) > 0 {
			validProtocolIDs = make([]string, 0, len(payload.ProtocolIDs))
			for _, pid := range payload.ProtocolIDs {
				trimmed := strings.TrimSpace(pid)
				if trimmed != "" {
					validProtocolIDs = append(validProtocolIDs, trimmed)
				}
			}
		}

		protocolsUpdated := false
		if payload.ClearAllProtocols {
			updatedCfg.Protocols = []agent.ProtocolConfig{}
			protocolsUpdated = true
		} else if len(payload.Protocols) > 0 || len(validProtocolIDs) > 0 {
			updatedCfg.Protocols = a.updateAgentProtocols(payload.Protocols, existingCfg.Protocols, validProtocolIDs)
			protocolsUpdated = true
		}
		// If neither ClearAllProtocols nor valid protocols were provided, preserve existingCfg.Protocols defensively.

		// Governance Retention Transition Logic:
		// Stash detached protocol governance rules in RetainedGovernance BEFORE overwriting ToolGovernance with payload!
		if protocolsUpdated {
			newProtoSet := make(map[string]bool, len(updatedCfg.Protocols))
			for _, p := range updatedCfg.Protocols {
				pid := p.ID
				if pid == "" {
					pid = p.Name
				}
				newProtoSet[strings.ToLower(pid)] = true
			}

			manifest, _ := repo.GetAgentManifest(agentName)

			for _, oldP := range existingCfg.Protocols {
				oldPID := oldP.ID
				if oldPID == "" {
					oldPID = oldP.Name
				}
				if !newProtoSet[strings.ToLower(oldPID)] {
					// Protocol was detached! Stash its tool governance rules in RetainedGovernance
					for toolName, mode := range existingCfg.ToolGovernance {
						if toolBelongsToProtocol(toolName, oldPID, oldP.Name, manifest) {
							if updatedCfg.RetainedGovernance == nil {
								updatedCfg.RetainedGovernance = make(map[string]map[string]agent.ToolGovernanceMode)
							}
							if updatedCfg.RetainedGovernance[oldPID] == nil {
								updatedCfg.RetainedGovernance[oldPID] = make(map[string]agent.ToolGovernanceMode)
							}
							updatedCfg.RetainedGovernance[oldPID][toolName] = mode
							delete(updatedCfg.ToolGovernance, toolName)
						}
					}
				}
			}

			// Handle restoration of retained protocols
			for _, restorePID := range payload.RestoreRetainedProtocols {
				pidClean := strings.TrimSpace(restorePID)
				for retainedKey, savedRules := range updatedCfg.RetainedGovernance {
					if strings.EqualFold(retainedKey, pidClean) {
						if updatedCfg.ToolGovernance == nil {
							updatedCfg.ToolGovernance = make(map[string]agent.ToolGovernanceMode, len(savedRules))
						}
						for toolName, mode := range savedRules {
							updatedCfg.ToolGovernance[toolName] = mode
						}
						delete(updatedCfg.RetainedGovernance, retainedKey)
					}
				}
			}
		}

		if payload.EnabledTools != nil {
			updatedCfg.EnabledTools = payload.EnabledTools
		}
		if payload.ToolOverrides != nil {
			updatedCfg.ToolOverrides = payload.ToolOverrides
		}
		if payload.ToolGovernance != nil {
			updatedCfg.ToolGovernance = make(map[string]agent.ToolGovernanceMode, len(payload.ToolGovernance))
			for k, v := range payload.ToolGovernance {
				updatedCfg.ToolGovernance[k] = v
			}
		}

		if payload.RetainedGovernance != nil {
			if updatedCfg.RetainedGovernance == nil {
				updatedCfg.RetainedGovernance = make(map[string]map[string]agent.ToolGovernanceMode, len(payload.RetainedGovernance))
			}
			for k, v := range payload.RetainedGovernance {
				toolsMap := make(map[string]agent.ToolGovernanceMode, len(v))
				for tk, tv := range v {
					toolsMap[tk] = tv
				}
				updatedCfg.RetainedGovernance[k] = toolsMap
			}
		}

		if payload.RateLimit != nil {
			updatedCfg.RateLimit = payload.RateLimit
		}
		if payload.LoopProtection != nil {
			updatedCfg.LoopProtection = payload.LoopProtection
		}

		// SaveAgentConfig automatically archives prior state to archive/<timestamp>/
		if err := repo.SaveAgentConfig(agentName, updatedCfg); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "UPDATE_FAILED",
				"message": err.Error(),
			})
			return
		}

		// Refresh tool discovery only if protocols were legitimately updated
		if protocolsUpdated {
			_, _ = a.syncAgentToolsProbed(r.Context(), agentName, updatedCfg)
		}

		toolsMeta, _ := repo.GetAgentManifest(agentName)
		effectiveTools := updatedCfg.ComputeEffectiveTools(toolsMeta)

		a.mu.RLock()
		reloadFn := a.reloadFunc
		a.mu.RUnlock()
		if reloadFn != nil {
			if err := reloadFn(); err != nil {
				slog.WarnContext(r.Context(), "Failed to reload runtime configuration after agent mutation", slog.String("agent", agentName), slog.String("error", err.Error()))
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "updated",
			"agent": map[string]interface{}{
				"name":            agentName,
				"routing_mode":    updatedCfg.RoutingMode,
				"config":          updatedCfg.MaskSecrets(),
				"tools":           toolsMeta,
				"effective_tools": effectiveTools,
				"status":          "active",
			},
		})
		return

	case http.MethodDelete:
		w.Header().Set("Content-Type", "application/json")
		agentName := relPath
		if agentName == "" {
			agentName = r.URL.Query().Get("name")
		}
		if agentName == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Agent name is required",
			})
			return
		}

		if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid agent name: " + err.Error(),
			})
			return
		}

		if _, err := repo.GetAgentConfig(agentName); err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Agent '%s' not found", agentName),
			})
			return
		}

		// Active session guard
		a.mu.Lock()
		sessChecker := a.activeSessionChecker
		a.mu.Unlock()
		if sessChecker != nil && sessChecker(agentName) {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "AGENT_IN_USE",
				"message": fmt.Sprintf("Agent '%s' has active client sessions and cannot be deleted", agentName),
			})
			return
		}

		if err := repo.DeleteAgent(agentName); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "DELETE_FAILED",
				"message": err.Error(),
			})
			return
		}

		a.mu.RLock()
		reloadFn := a.reloadFunc
		a.mu.RUnlock()
		if reloadFn != nil {
			if err := reloadFn(); err != nil {
				slog.WarnContext(r.Context(), "Failed to reload runtime configuration after agent mutation", slog.String("agent", agentName), slog.String("error", err.Error()))
			}
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Agent '%s' successfully deleted", agentName),
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
