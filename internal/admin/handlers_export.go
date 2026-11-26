package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/mcpexport"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

type exportAgentNativeMCPRequest struct {
	Client   string `json:"client"`
	Scope    string `json:"scope,omitempty"`
	ClientOS string `json:"client_os,omitempty"`
}

// handleExportAgentNativeMCP exports a Security Profile's current attached Tool Sources
// in a Target Client's native MCP JSON format without raw secrets (POST /admin/agents/{name}/export).
func (a *AdminServer) handleExportAgentNativeMCP(w http.ResponseWriter, r *http.Request) {
	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}

	agentName := r.PathValue("name")
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid agent name: "+err.Error())
		return
	}

	var payload exportAgentNativeMCPRequest
	if err := decodeJSON(w, r, maxAdminBodyBytes, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	if _, _, _, err := mcpexport.ResolveTargetMeta(payload.Client, payload.Scope, payload.ClientOS); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_EXPORT_TARGET", err.Error())
		return
	}

	cfg, err := repo.GetAgentConfig(agentName)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Agent '%s' not found", agentName))
		return
	}

	manifest, _ := repo.GetAgentManifest(agentName)

	var lookup mcpexport.ProtocolLookup
	if a.protocolStore != nil {
		lookup = func(id string) (*protocol.Protocol, bool) {
			p, err := a.protocolStore.Get(id)
			if err != nil || p == nil {
				return nil, false
			}
			return p, true
		}
	}

	result, err := mcpexport.Export(r.Context(), mcpexport.ExportRequest{
		Client:   payload.Client,
		Scope:    payload.Scope,
		ClientOS: payload.ClientOS,
		Route:    cfg,
		Manifest: manifest,
		Lookup:   lookup,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusRequestTimeout, "REQUEST_TIMEOUT", "Export timed out")
			return
		}
		writeError(w, http.StatusBadRequest, "EXPORT_FAILED", err.Error())
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	a.logSecurityAudit(r, "agent_native_export", "export", "agent", agentName, "allowed", "Direct Native MCP export generated", map[string]any{
		"client":        result.Client,
		"scope":         result.Scope,
		"warning_count": len(result.Warnings),
	})

	writeJSON(w, http.StatusOK, result)
}
