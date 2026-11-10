package admin

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
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

func cloneProtocolConfig(p agent.ProtocolConfig) agent.ProtocolConfig {
	cp := p
	cp.Args = slices.Clone(p.Args)
	cp.Env = slices.Clone(p.Env)
	cp.AllowedTools = slices.Clone(p.AllowedTools)
	cp.Headers = maps.Clone(p.Headers)
	return cp
}

func (a *AdminServer) enrichAgentProtocols(protocols []agent.ProtocolConfig, protocolIDs []string) []agent.ProtocolConfig {
	res := make([]agent.ProtocolConfig, len(protocols))
	for i := range protocols {
		res[i] = cloneProtocolConfig(protocols[i])
	}

	store := a.getProtocolStore()
	if store == nil {
		return res
	}

	for i := range res {
		if def := findProtocolDef(store, res[i].ID, res[i].Name); def != nil {
			applyProtocolDefaults(&res[i], def, true)
		}
	}

	for _, rawID := range protocolIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || containsProtocol(res, id) {
			continue
		}
		if def, err := store.Get(id); err == nil && def != nil {
			var cfg agent.ProtocolConfig
			applyProtocolDefaults(&cfg, def, true)
			res = append(res, cfg)
		}
	}

	return res
}

// updateAgentProtocols preserves agent-specific overrides first by hydrating masked placeholders from
// existing agent protocols before applying non-clobbering metadata/defaults from the global protocol store.
func (a *AdminServer) updateAgentProtocols(incoming, existing []agent.ProtocolConfig, protocolIDs []string) []agent.ProtocolConfig {
	res := make([]agent.ProtocolConfig, len(incoming))
	for i := range incoming {
		res[i] = cloneProtocolConfig(incoming[i])
	}

	hadExisting := hydrateProtocolsFromExisting(res, existing)

	store := a.getProtocolStore()
	if store == nil {
		return res
	}

	for i := range res {
		if def := findProtocolDef(store, res[i].ID, res[i].Name); def != nil {
			// Only seed default secrets/env/headers when attaching a protocol not already present on the agent.
			applyProtocolDefaults(&res[i], def, !hadExisting[i])
		}
	}

	for _, rawID := range protocolIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || containsProtocol(res, id) {
			continue
		}
		if def, err := store.Get(id); err == nil && def != nil {
			var cfg agent.ProtocolConfig
			applyProtocolDefaults(&cfg, def, true)
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

func mergeUnmaskedEnv(dstEnv, srcEnv []string, fillWhenEmpty bool) []string {
	if len(dstEnv) == 0 {
		if fillWhenEmpty {
			return slices.Clone(srcEnv)
		}
		return dstEnv
	}
	if len(srcEnv) == 0 {
		return dstEnv
	}
	srcByKey := make(map[string]string, len(srcEnv))
	for _, entry := range srcEnv {
		if k, v, ok := strings.Cut(entry, "="); ok {
			srcByKey[k] = v
		}
	}
	merged := make([]string, len(dstEnv))
	for i, entry := range dstEnv {
		merged[i] = entry
		k, v, ok := strings.Cut(entry, "=")
		if ok && strings.Contains(v, "••••••") {
			if orig, found := srcByKey[k]; found {
				merged[i] = k + "=" + orig
			}
		}
	}
	return merged
}

func hydrateProtocolsFromExisting(dst, existing []agent.ProtocolConfig) []bool {
	matched := make([]bool, len(dst))
	if len(dst) == 0 || len(existing) == 0 {
		return matched
	}
	for i := range dst {
		var match *agent.ProtocolConfig
		for j := range existing {
			if (dst[i].ID != "" && strings.EqualFold(dst[i].ID, existing[j].ID)) ||
				(dst[i].Name != "" && strings.EqualFold(dst[i].Name, existing[j].Name)) {
				match = &existing[j]
				break
			}
		}
		if match == nil {
			continue
		}
		matched[i] = true
		if strings.Contains(dst[i].AuthToken, "••••••") {
			dst[i].AuthToken = match.AuthToken
		}
		dst[i].Env = mergeUnmaskedEnv(dst[i].Env, match.Env, false)
		for k, v := range dst[i].Headers {
			if strings.Contains(v, "••••••") {
				if orig, ok := match.Headers[k]; ok {
					dst[i].Headers[k] = orig
				}
			}
		}
	}
	return matched
}

func applyProtocolDefaults(dst *agent.ProtocolConfig, src *protocol.Protocol, fillCredentials bool) {
	dst.ID = cmp.Or(dst.ID, src.ID)
	dst.Name = cmp.Or(dst.Name, src.Name)
	dst.Type = cmp.Or(dst.Type, src.Type)
	dst.Command = cmp.Or(dst.Command, src.Command)
	dst.URLOrCommand = cmp.Or(dst.URLOrCommand, src.URLOrCommand, src.Command)

	if len(dst.Args) == 0 && len(src.Args) > 0 {
		dst.Args = slices.Clone(src.Args)
	}
	if len(dst.AllowedTools) == 0 && len(src.AllowedTools) > 0 {
		dst.AllowedTools = slices.Clone(src.AllowedTools)
	}
	dst.Env = mergeUnmaskedEnv(dst.Env, src.Env, fillCredentials)
	if fillCredentials {
		if dst.AuthToken == "" || strings.Contains(dst.AuthToken, "••••••") {
			dst.AuthToken = src.AuthToken
		}
		if len(dst.Headers) == 0 {
			dst.Headers = maps.Clone(src.Headers)
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
}

func (a *AdminServer) syncAgentToolsProbed(ctx context.Context, agentName string, agentCfg *agent.RouteConfig) ([]map[string]interface{}, error) {
	repo := a.getAgentRepository()
	var allDiscoveredTools []map[string]interface{}
	var probeErrors []string

	ssrfOpts := transport.DefaultSafeOptions()
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if cfg != nil {
		ssrfOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
	}
	timeout := a.probeTimeout()

	for _, proto := range agentCfg.Protocols {
		protoName := proto.Name
		protoID := proto.ID
		var rawTools []map[string]interface{}
		var pErr error

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		if proto.IsStdio() {
			cmd := proto.GetCommand()
			if cmd != "" {
				rawTools, pErr = ProbeAndDiscoverMCPToolsStdio(probeCtx, cmd, proto.Args, proto.Env)
			}
		} else if proto.URLOrCommand != "" {
			rawTools, pErr = ProbeAndDiscoverMCPToolsWithContextAuthAndHeaders(probeCtx, a.SafeHTTPClient(), proto.URLOrCommand, proto.AuthToken, proto.Headers, ssrfOpts)
		}
		cancel()

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
