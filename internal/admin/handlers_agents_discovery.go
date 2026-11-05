package admin

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
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

	store := a.getProtocolStore()
	if store == nil {
		return res
	}

	for i := range res {
		if def := findProtocolDef(store, res[i].ID, res[i].Name); def != nil {
			applyProtocolDefaults(&res[i], def)
		}
	}

	for _, rawID := range protocolIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || containsProtocol(res, id) {
			continue
		}
		if def, err := store.Get(id); err == nil && def != nil {
			var cfg agent.ProtocolConfig
			applyProtocolDefaults(&cfg, def)
			res = append(res, cfg)
		}
	}

	return res
}

func findProtocolDef(store protocol.Store, ids ...string) *protocol.Protocol {
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			if def, err := store.Get(id); err == nil && def != nil {
				return def
			}
		}
	}
	return nil
}

func containsProtocol(list []agent.ProtocolConfig, id string) bool {
	return slices.ContainsFunc(list, func(p agent.ProtocolConfig) bool {
		return strings.EqualFold(p.ID, id) || strings.EqualFold(p.Name, id)
	})
}

func applyProtocolDefaults(dst *agent.ProtocolConfig, src *protocol.Protocol) {
	dst.ID = cmp.Or(dst.ID, src.ID)
	dst.Name = cmp.Or(dst.Name, src.Name)
	dst.Type = cmp.Or(dst.Type, src.Type)
	dst.Command = cmp.Or(dst.Command, src.Command)
	dst.URLOrCommand = cmp.Or(dst.URLOrCommand, src.URLOrCommand, src.Command)

	if len(dst.Args) == 0 {
		dst.Args = src.Args
	}
	if len(dst.Env) == 0 {
		dst.Env = src.Env
	}
	if len(dst.AllowedTools) == 0 {
		dst.AllowedTools = src.AllowedTools
	}
	if dst.AuthToken == "" || strings.Contains(dst.AuthToken, "••••••") {
		dst.AuthToken = src.AuthToken
	}
	if len(dst.Headers) == 0 {
		dst.Headers = src.Headers
		return
	}
	for k, v := range dst.Headers {
		if strings.Contains(v, "••••••") {
			if orig, ok := src.Headers[k]; ok {
				dst.Headers[k] = orig
			}
		}
	}
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

