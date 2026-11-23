package admin

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

func (a *AdminServer) getAgentRepository() agent.Repository {
	return a.agentRepo
}

func (a *AdminServer) requireAgentRepository(w http.ResponseWriter) agent.Repository {
	repo := a.getAgentRepository()
	if repo == nil {
		writeError(w, http.StatusServiceUnavailable, "REPO_UNAVAILABLE", "Agent repository is not initialized")
		return nil
	}
	return repo
}

func buildAgentPayloadMap(agentName string, cfg *agent.RouteConfig, tools any, effectiveTools []agent.ToolMetadata) map[string]interface{} {
	routingMode := cmp.Or(cfg.RoutingMode, "aggregated")
	return map[string]interface{}{
		"name":            agentName,
		"routing_mode":    routingMode,
		"config":          cfg.MaskSecrets(),
		"tools":           tools,
		"effective_tools": effectiveTools,
		"status":          "active",
	}
}

func (a *AdminServer) triggerBestEffortReload(r *http.Request, agentName string) {
	if a.reloadFunc == nil {
		return
	}
	if err := a.reloadFunc(); err != nil {
		slog.WarnContext(r.Context(), "Failed to reload runtime configuration after agent mutation",
			slog.String("agent", agentName),
			slog.String("error", err.Error()))
	}
}

// handleListAgents returns all active agents with masked configs and effective tools (GET /admin/agents).
func (a *AdminServer) handleListAgents(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	snapshots, err := repo.ListAgentSnapshots()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"agents": []interface{}{}})
		return
	}

	var agents []map[string]interface{}
	for _, snap := range snapshots {
		effectiveTools := snap.Config.ComputeEffectiveTools(snap.Manifest)
		agents = append(agents, buildAgentPayloadMap(snap.Name, snap.Config, snap.Manifest, effectiveTools))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"agents": agents})
}

// handleGetAgent returns a single agent's masked configuration and tools (GET /admin/agents/{name}).
func (a *AdminServer) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	agentName := r.PathValue("name")
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid agent name: "+err.Error())
		return
	}

	cfg, err := repo.GetAgentConfig(agentName)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Agent '%s' not found", agentName))
		return
	}

	tools, _ := repo.GetAgentManifest(agentName)
	effectiveTools := cfg.ComputeEffectiveTools(tools)
	writeJSON(w, http.StatusOK, buildAgentPayloadMap(agentName, cfg, tools, effectiveTools))
}

// handleCreateAgent creates a new agent profile, probes attached protocols, and saves its manifest (POST /admin/agents).
func (a *AdminServer) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	var payload AgentPayload
	if err := decodeJSON(w, r, maxAdminBodyBytes, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	agentName := cmp.Or(
		strings.TrimSpace(payload.AgentName),
		strings.TrimSpace(payload.Name),
		strings.TrimSpace(payload.AgentID),
	)
	if agentName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "agent_name is required")
		return
	}
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid agent name: "+err.Error())
		return
	}
	if existing, _ := repo.GetAgentConfig(agentName); existing != nil {
		writeError(w, http.StatusConflict, "AGENT_ALREADY_EXISTS", fmt.Sprintf("Agent '%s' already exists. Use PUT to update.", agentName))
		return
	}
	if !validateAgentPayload(w, payload) {
		return
	}

	routingMode := cmp.Or(strings.ToLower(strings.TrimSpace(payload.RoutingMode)), "aggregated")
	enrichedProtocols := a.enrichAgentProtocols(payload.Protocols, payload.ProtocolIDs)
	if !a.isStdioAllowed() && rejectStdioAgentProtocols(w, enrichedProtocols) {
		return
	}
	cfg := &agent.RouteConfig{
		AgentID:            agentName,
		AgentName:          agentName,
		Description:        payload.Description,
		RoutingMode:        routingMode,
		Protocols:          enrichedProtocols,
		EnabledTools:       payload.EnabledTools,
		ToolOverrides:      payload.ToolOverrides,
		ToolGovernance:     payload.ToolGovernance,
		RetainedGovernance: payload.RetainedGovernance,
		RateLimit:          payload.RateLimit,
		LoopProtection:     payload.LoopProtection,
		SchemaValidation:   payload.SchemaValidation,
		Guard:              payload.Guard,
	}

	if err := repo.SaveAgentConfig(agentName, cfg); err != nil {
		slog.ErrorContext(r.Context(), "Failed to persist new agent configuration", slog.String("agent", agentName), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", "Failed to save agent configuration")
		return
	}

	discoveredTools, _ := a.syncAgentToolsProbed(r.Context(), agentName, cfg)
	toolsMeta, _ := repo.GetAgentManifest(agentName)
	effectiveTools := cfg.ComputeEffectiveTools(toolsMeta)
	a.triggerBestEffortReload(r, agentName)
	a.logSecurityAudit(r, "agent_mutated", "create", "agent", agentName, "allowed", "Agent profile created", map[string]any{
		"routing_mode": routingMode,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status": "created",
		"agent":  buildAgentPayloadMap(agentName, cfg, discoveredTools, effectiveTools),
	})
}

// handleUpdateAgent updates an existing agent profile, archiving the prior snapshot (PUT /admin/agents/{name}).
func (a *AdminServer) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	agentName := r.PathValue("name")
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid agent name: "+err.Error())
		return
	}

	existingCfg, err := repo.GetAgentConfig(agentName)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Agent '%s' not found", agentName))
		return
	}

	var payload AgentPayload
	if err := decodeJSON(w, r, maxAdminBodyBytes, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	if !validateAgentPayload(w, payload) {
		return
	}

	nextProtocols, protocolsUpdated := a.resolveNextAgentProtocols(payload, existingCfg.Protocols)
	if protocolsUpdated && !a.isStdioAllowed() && rejectStdioAgentProtocols(w, nextProtocols) {
		return
	}

	var manifest []agent.ToolMetadata
	if protocolsUpdated {
		manifest, _ = repo.GetAgentManifest(agentName)
	}

	updatedCfg := existingCfg.Clone()
	updatedCfg.ApplyUpdate(payload.ToUpdateSpec(nextProtocols, protocolsUpdated), manifest)

	if err := repo.SaveAgentConfig(agentName, updatedCfg); err != nil {
		slog.ErrorContext(r.Context(), "Failed to update agent configuration", slog.String("agent", agentName), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Failed to update agent configuration")
		return
	}

	if protocolsUpdated {
		_, _ = a.syncAgentToolsProbed(r.Context(), agentName, updatedCfg)
	}

	toolsMeta, _ := repo.GetAgentManifest(agentName)
	effectiveTools := updatedCfg.ComputeEffectiveTools(toolsMeta)
	a.triggerBestEffortReload(r, agentName)
	a.logSecurityAudit(r, "agent_mutated", "update", "agent", agentName, "allowed", "Agent profile updated", map[string]any{
		"protocols_updated": protocolsUpdated,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "updated",
		"agent":  buildAgentPayloadMap(agentName, updatedCfg, toolsMeta, effectiveTools),
	})
}

func (a *AdminServer) resolveNextAgentProtocols(payload AgentPayload, existing []agent.ProtocolConfig) ([]agent.ProtocolConfig, bool) {
	if payload.ClearAllProtocols {
		return []agent.ProtocolConfig{}, true
	}
	var validProtocolIDs []string
	for _, pid := range payload.ProtocolIDs {
		if trimmed := strings.TrimSpace(pid); trimmed != "" {
			validProtocolIDs = append(validProtocolIDs, trimmed)
		}
	}
	if len(payload.Protocols) == 0 && len(validProtocolIDs) == 0 {
		return nil, false
	}
	return a.updateAgentProtocols(payload.Protocols, existing, validProtocolIDs), true
}

// handleDeleteAgent removes an agent profile if no active sessions depend on it (DELETE /admin/agents/{name}).
func (a *AdminServer) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	agentName := cmp.Or(r.PathValue("name"), r.URL.Query().Get("name"))
	if agentName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Agent name is required")
		return
	}
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid agent name: "+err.Error())
		return
	}
	if _, err := repo.GetAgentConfig(agentName); err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Agent '%s' not found", agentName))
		return
	}

	if a.activeSessionChecker != nil && a.activeSessionChecker(agentName) {
		writeError(w, http.StatusConflict, "AGENT_IN_USE", fmt.Sprintf("Agent '%s' has active client sessions and cannot be deleted", agentName))
		return
	}

	if err := repo.DeleteAgent(agentName); err != nil {
		slog.ErrorContext(r.Context(), "Failed to delete agent configuration", slog.String("agent", agentName), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "DELETE_FAILED", "Failed to delete agent configuration")
		return
	}

	a.triggerBestEffortReload(r, agentName)
	a.logSecurityAudit(r, "agent_mutated", "delete", "agent", agentName, "allowed", "Agent profile deleted", nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Agent '%s' successfully deleted", agentName),
	})
}

func validateAgentPayload(w http.ResponseWriter, payload AgentPayload) bool {
	if vErr := payload.ToUpdateSpec(nil, false).Validate(); vErr != nil {
		writeError(w, http.StatusBadRequest, vErr.Code, vErr.Error())
		return false
	}
	return true
}

func isAgentProtocolStdio(p agent.ProtocolConfig) bool {
	return p.IsStdio() || (strings.TrimSpace(p.Type) == "" && strings.TrimSpace(p.Command) != "")
}

func rejectStdioAgentProtocols(w http.ResponseWriter, protocols []agent.ProtocolConfig) bool {
	for _, p := range protocols {
		if isAgentProtocolStdio(p) {
			writeError(w, http.StatusBadRequest, "STDIO_DISABLED", stdioDisabledMsg)
			return true
		}
	}
	return false
}
