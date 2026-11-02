package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

// toolBelongsToProtocol determines if a tool is owned by a given protocol (via prefix or manifest lookup).
func toolBelongsToProtocol(toolName, protoID, protoName string, manifest []agent.ToolMetadata) bool {
	protoIDLower := strings.ToLower(strings.TrimSpace(protoID))
	protoNameLower := strings.ToLower(strings.TrimSpace(protoName))
	toolLower := strings.ToLower(toolName)

	if protoIDLower != "" && strings.HasPrefix(toolLower, protoIDLower+"__") {
		return true
	}
	if protoNameLower != "" && strings.HasPrefix(toolLower, protoNameLower+"__") {
		return true
	}

	for _, tm := range manifest {
		if strings.EqualFold(tm.Name, toolName) || strings.EqualFold(tm.CanonicalName, toolName) {
			if (protoIDLower != "" && strings.EqualFold(tm.ProtocolID, protoID)) ||
				(protoNameLower != "" && strings.EqualFold(tm.ProtocolName, protoName)) {
				return true
			}
		}
	}
	return false
}

func (a *AdminServer) enrichAgentProtocols(protocols []agent.ProtocolConfig, protocolIDs []string) []agent.ProtocolConfig {
	res := make([]agent.ProtocolConfig, len(protocols))
	copy(res, protocols)

	if len(protocolIDs) == 0 {
		return res
	}

	store := a.getProtocolStore()
	if store == nil {
		return res
	}

	for _, pid := range protocolIDs {
		trimmed := strings.TrimSpace(pid)
		if trimmed == "" {
			continue
		}
		alreadyExists := false
		for _, p := range res {
			if strings.EqualFold(p.ID, trimmed) || strings.EqualFold(p.Name, trimmed) {
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}

		pDef, err := store.Get(trimmed)
		if err == nil && pDef != nil {
			urlOrCmd := pDef.URLOrCommand
			if urlOrCmd == "" && pDef.Command != "" {
				urlOrCmd = pDef.Command
			}
			res = append(res, agent.ProtocolConfig{
				ID:           pDef.ID,
				Name:         pDef.Name,
				Type:         pDef.Type,
				URLOrCommand: urlOrCmd,
				Command:      pDef.Command,
				Args:         pDef.Args,
				Env:          pDef.Env,
				AllowedTools: pDef.AllowedTools,
			})
		}
	}

	return res
}

func (a *AdminServer) syncAgentToolsProbed(ctx context.Context, agentName string, agentCfg *agent.RouteConfig) ([]map[string]interface{}, error) {
	repo := a.getAgentRepository()
	var allDiscoveredTools []map[string]interface{}
	var probeErrors []string

	for _, proto := range agentCfg.Protocols {
		protoName := proto.Name
		protoID := proto.ID
		var rawTools []map[string]interface{}
		var pErr error

		if proto.IsStdio() {
			cmd := proto.GetCommand()
			if cmd != "" {
				rawTools, pErr = ProbeAndDiscoverMCPToolsStdio(ctx, cmd, proto.Args, proto.Env)
			}
		} else if proto.URLOrCommand != "" {
			rawTools, pErr = ProbeAndDiscoverMCPToolsWithContextAuthAndHeaders(ctx, a.SafeHTTPClient(), proto.URLOrCommand, proto.AuthToken, proto.Headers, transport.DefaultSafeOptions())
		}

		if pErr != nil || len(rawTools) == 0 {
			if pErr != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("%s -> %v", protoName, pErr))
			}
			continue
		}

		for _, t := range rawTools {
			toolCopy := make(map[string]interface{})
			for k, v := range t {
				toolCopy[k] = v
			}
			rawName, _ := t["name"].(string)
			if rawName == "" {
				rawName, _ = t["raw_name"].(string)
			}
			toolCopy["raw_name"] = rawName
			protoSlug := protoID
			if protoSlug == "" {
				protoSlug = protoName
			}
			if agentCfg.IsAggregated() && protoSlug != "" {
				cleanRaw := strings.TrimPrefix(rawName, protoSlug+"__")
				toolCopy["name"] = fmt.Sprintf("%s__%s", protoSlug, cleanRaw)
				toolCopy["canonical_name"] = fmt.Sprintf("%s__%s", protoSlug, cleanRaw)
			} else {
				toolCopy["name"] = rawName
				toolCopy["canonical_name"] = rawName
			}
			toolCopy["protocol_name"] = protoName
			toolCopy["protocol_id"] = protoID

			allDiscoveredTools = append(allDiscoveredTools, toolCopy)
		}
	}

	if repo != nil {
		if allDiscoveredTools == nil {
			allDiscoveredTools = make([]map[string]interface{}, 0)
		}
		_ = repo.SaveAgentManifest(agentName, allDiscoveredTools)
	}

	if len(probeErrors) > 0 {
		return allDiscoveredTools, fmt.Errorf("probe warnings: %s", strings.Join(probeErrors, " | "))
	}
	return allDiscoveredTools, nil
}

func (a *AdminServer) handleAgentSyncTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		AgentName string `json:"agent_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentName == "" {
		http.Error(w, "Invalid agent_name", http.StatusBadRequest)
		return
	}

	if err := pathguard.ValidateSafeIdentifier(req.AgentName); err != nil {
		http.Error(w, "Security violation: invalid agent_name: "+err.Error(), http.StatusBadRequest)
		return
	}

	repo := a.getAgentRepository()
	agentCfg, err := repo.GetAgentConfig(req.AgentName)
	if err != nil {
		http.Error(w, "Agent config not found: "+err.Error(), http.StatusNotFound)
		return
	}

	allDiscoveredTools, pErr := a.syncAgentToolsProbed(r.Context(), req.AgentName, agentCfg)
	if len(allDiscoveredTools) == 0 && pErr != nil {
		http.Error(w, "No live tools discovered. Diagnostics: "+pErr.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"tools":  allDiscoveredTools,
	})
}

