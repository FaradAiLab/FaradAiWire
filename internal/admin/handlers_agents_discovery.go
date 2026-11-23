package admin

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpprobe"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

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
		dst[i].AuthToken = protocol.PreserveMaskedSecret(dst[i].AuthToken, match.AuthToken, false)
		dst[i].Env = protocol.MergeMaskedEnv(dst[i].Env, match.Env, false)
		dst[i].Headers = protocol.MergeMaskedHeaders(dst[i].Headers, match.Headers, false)
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
	dst.Env = protocol.MergeMaskedEnv(dst.Env, src.Env, fillCredentials)
	if fillCredentials {
		dst.AuthToken = protocol.PreserveMaskedSecret(dst.AuthToken, src.AuthToken, true)
		dst.Headers = protocol.MergeMaskedHeaders(dst.Headers, src.Headers, true)
	}
}

const maxConcurrentProbes = 4

type protocolProbeOutcome struct {
	proto agent.ProtocolConfig
	tools []map[string]interface{}
	err   error
}

func (a *AdminServer) probeSingleProtocol(ctx context.Context, proto agent.ProtocolConfig, ssrfOpts transport.SafeTransportOptions, baseTimeout time.Duration) protocolProbeOutcome {
	if !a.isStdioAllowed() && isAgentProtocolStdio(proto) {
		return protocolProbeOutcome{
			proto: proto,
			err:   errors.New("stdio subprocess execution is disabled (allow_stdio=false)"),
		}
	}
	protoTimeout := baseTimeout
	if proto.IsStdio() {
		protoTimeout = a.stdioProbeTimeout(proto.GetCommand())
	}
	probeCtx, cancel := context.WithTimeout(ctx, protoTimeout)
	defer cancel()

	var (
		rawTools []map[string]interface{}
		pErr     error
	)
	if proto.IsStdio() {
		if cmd := proto.GetCommand(); cmd != "" {
			rawTools, pErr = mcpprobe.ProbeStdio(probeCtx, mcpprobe.StdioProbeRequest{
				Command: cmd,
				Args:    proto.Args,
				Env:     proto.Env,
			})
		}
	} else if proto.URLOrCommand != "" {
		var res *mcpprobe.ProbeResult
		res, pErr = mcpprobe.ProbeHTTP(probeCtx, mcpprobe.ProbeRequest{
			Client:        a.SafeHTTPClient(),
			TargetURL:     proto.URLOrCommand,
			AuthToken:     proto.AuthToken,
			CustomHeaders: proto.Headers,
			SSRFOptions:   ssrfOpts,
		})
		if res != nil {
			rawTools = res.Tools
		}
	}

	return protocolProbeOutcome{
		proto: proto,
		tools: rawTools,
		err:   pErr,
	}
}

func (a *AdminServer) syncAgentToolsProbed(ctx context.Context, agentName string, agentCfg *agent.RouteConfig) ([]map[string]interface{}, error) {
	repo := a.getAgentRepository()
	var allDiscoveredTools []map[string]interface{}
	var probeErrors []string

	ssrfOpts := transport.DefaultSafeOptions()
	if cfg := a.Config(); cfg != nil {
		ssrfOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
	}
	timeout := a.probeTimeout()

	outcomes := make([]protocolProbeOutcome, len(agentCfg.Protocols))
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup

	for i, proto := range agentCfg.Protocols {
		wg.Add(1)
		go func(idx int, p agent.ProtocolConfig) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				outcomes[idx] = protocolProbeOutcome{proto: p, err: ctx.Err()}
				return
			}
			outcomes[idx] = a.probeSingleProtocol(ctx, p, ssrfOpts, timeout)
		}(i, proto)
	}
	wg.Wait()

	for _, outcome := range outcomes {
		proto := outcome.proto
		protoName := proto.Name
		protoID := proto.ID

		if outcome.err != nil || len(outcome.tools) == 0 {
			if outcome.err != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("%s -> %v", protoName, outcome.err))
			}
			continue
		}

		for _, t := range outcome.tools {
			toolCopy := make(map[string]interface{})
			for k, v := range t {
				toolCopy[k] = v
			}
			rawName, _ := t["name"].(string)
			if rawName == "" {
				rawName, _ = t["raw_name"].(string)
			}
			toolCopy["raw_name"] = rawName
			protoSlug := agent.ResolveToolSlug(&proto, protoID, protoName)
			if agentCfg.IsAggregated() && protoSlug != "" {
				formatted := agent.FormatAggregatedToolName(protoSlug, rawName)
				toolCopy["name"] = formatted
				toolCopy["canonical_name"] = formatted
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
	var req struct {
		AgentName string `json:"agent_name"`
	}
	if err := decodeJSON(w, r, maxAdminBodyBytes, &req); err != nil || req.AgentName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid agent_name")
		return
	}

	if err := pathguard.ValidateSafeIdentifier(req.AgentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Security violation: invalid agent_name: "+err.Error())
		return
	}

	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}
	agentCfg, err := repo.GetAgentConfig(req.AgentName)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Agent config not found: "+err.Error())
		return
	}

	allDiscoveredTools, pErr := a.syncAgentToolsProbed(r.Context(), req.AgentName, agentCfg)
	if len(allDiscoveredTools) == 0 && pErr != nil {
		writeError(w, http.StatusBadGateway, "PROBE_FAILED", "No live tools discovered. Diagnostics: "+pErr.Error())
		return
	}

	a.logSecurityAudit(r, "agent_mutated", "sync_tools", "agent", req.AgentName, "allowed", "Agent tools synchronized", map[string]any{
		"tools_count": len(allDiscoveredTools),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"tools":  allDiscoveredTools,
	})
}
