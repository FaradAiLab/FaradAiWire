package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

func (a *AdminServer) requireAgentDLPContext(w http.ResponseWriter, r *http.Request) (string, policy.Store, *policy.Compiler, bool) {
	agentName := r.PathValue("name")
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_AGENT_IDENTIFIER", err.Error())
		return "", nil, nil, false
	}

	store := a.getPolicyStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "POLICY_STORE_UNAVAILABLE", "Policy store is not initialized")
		return "", nil, nil, false
	}
	return agentName, store, a.getPolicyCompiler(), true
}

// handleGetAgentDLP returns saved and compiled DLP governance configuration for an agent (GET /admin/agents/{name}/dlp).
func (a *AdminServer) handleGetAgentDLP(w http.ResponseWriter, r *http.Request) {
	agentName, store, compiler, ok := a.requireAgentDLPContext(w, r)
	if !ok {
		return
	}

	cfg, err := store.GetAgentConfig(r.Context(), agentName)
	if err != nil {
		if !errors.Is(err, policy.ErrConfigNotFound) {
			writeError(w, http.StatusInternalServerError, "GET_AGENT_CONFIG_FAILED", err.Error())
			return
		}
		if recCfg := a.reconcileAgentDLPFromDisk(r.Context(), agentName, store); recCfg != nil {
			cfg = recCfg
		} else {
			cfg = &policy.AgentPolicyConfig{
				AgentName:      agentName,
				PackIDs:        []string{},
				Overrides:      []policy.RuleOverride{},
				CustomPatterns: []policy.CustomPattern{},
				ToolExemptions: make(map[string]policy.ToolExemption),
			}
		}
	}

	var compiled *policy.CompiledAgentPolicy
	if compiler != nil {
		if comp, cErr := compiler.Compile(r.Context(), cfg); cErr == nil {
			compiled = comp
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_name": agentName,
		"config":     cfg,
		"compiled":   compiled,
	})
}

// handleUpdateAgentDLP persists and compiles an agent's DLP governance config (PUT /admin/agents/{name}/dlp).
func (a *AdminServer) handleUpdateAgentDLP(w http.ResponseWriter, r *http.Request) {
	agentName, store, compiler, ok := a.requireAgentDLPContext(w, r)
	if !ok {
		return
	}

	var cfg policy.AgentPolicyConfig
	if err := decodeJSON(w, r, maxAdminBodyBytes, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode agent DLP config: "+err.Error())
		return
	}
	cfg.AgentName = agentName

	if err := policy.ValidateAgentPolicyConfig(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	// Enforce atomic rollback parity: snapshot current agent state before updating DLP.
	if repo := a.getAgentRepository(); repo != nil {
		if err := repo.ArchiveAgentCurrent(agentName); err != nil {
			slog.WarnContext(r.Context(), "Failed to create agent snapshot archive before saving DLP", "agent", agentName, "error", err)
		}
	}

	if compiler != nil {
		if err := compiler.SaveConfigAndCompile(r.Context(), &cfg); err != nil {
			writeError(w, http.StatusInternalServerError, "COMPILE_AND_SAVE_FAILED", err.Error())
			return
		}
	} else if err := store.SaveAgentConfig(r.Context(), &cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_AGENT_CONFIG_FAILED", err.Error())
		return
	}

	var compiled *policy.CompiledAgentPolicy
	if compiler != nil {
		compiled, _ = compiler.Compile(r.Context(), &cfg)
	}

	a.logSecurityAudit(r, "agent_dlp_updated", "update", "agent_dlp", agentName, "allowed", "Agent DLP configuration updated", map[string]any{
		"pack_count": len(cfg.PackIDs),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "saved",
		"agent_name": agentName,
		"config":     cfg,
		"compiled":   compiled,
	})
}

// reconcileAgentDLPFromDisk attempts to reconstruct an AgentPolicyConfig from an existing
// agents/<name>/current/dlp.json file when DuckDB lacks an agent_dlp_configs entry.
func (a *AdminServer) reconcileAgentDLPFromDisk(ctx context.Context, agentName string, store policy.Store) *policy.AgentPolicyConfig {
	agentsDir := (&config.Config{}).GetAgentsDir()
	if cfg := a.Config(); cfg != nil {
		agentsDir = cfg.GetAgentsDir()
	}
	if compiler := a.getPolicyCompiler(); compiler != nil && compiler.AgentsDir() != "" {
		agentsDir = compiler.AgentsDir()
	}
	dlpPath := filepath.Join(agentsDir, agentName, "current", "dlp.json")
	data, err := os.ReadFile(dlpPath)
	if err != nil {
		return nil
	}

	var diskPayload struct {
		Enabled  bool `json:"enabled"`
		Patterns []struct {
			Name   string `json:"name"`
			Regex  string `json:"regex"`
			Action string `json:"action"`
		} `json:"patterns"`
		ToolExemptions map[string]policy.ToolExemption `json:"tool_exemptions"`
	}
	if err := json.Unmarshal(data, &diskPayload); err != nil {
		return nil
	}
	if len(diskPayload.Patterns) == 0 && len(diskPayload.ToolExemptions) == 0 {
		return nil
	}

	cfg := &policy.AgentPolicyConfig{
		AgentName:      agentName,
		PackIDs:        []string{},
		Overrides:      []policy.RuleOverride{},
		CustomPatterns: []policy.CustomPattern{},
		ToolExemptions: diskPayload.ToolExemptions,
	}
	if cfg.ToolExemptions == nil {
		cfg.ToolExemptions = make(map[string]policy.ToolExemption)
	}

	packs, err := store.ListPacks(ctx)
	if err != nil {
		for _, p := range diskPayload.Patterns {
			cfg.CustomPatterns = append(cfg.CustomPatterns, policy.CustomPattern{
				Name:   p.Name,
				Regex:  p.Regex,
				Action: policy.Action(p.Action),
			})
		}
		_ = store.SaveAgentConfig(ctx, cfg)
		return cfg
	}

	allRules, err := store.ListRules(ctx, "")
	if err != nil {
		allRules = nil
	}
	ruleByID := make(map[string]policy.DlpPatternRule, len(allRules))
	for _, r := range allRules {
		ruleByID[r.ID] = r
	}

	type patTracker struct {
		name   string
		regex  string
		action string
		used   bool
	}
	trackers := make([]*patTracker, len(diskPayload.Patterns))
	for i, p := range diskPayload.Patterns {
		trackers[i] = &patTracker{
			name:   p.Name,
			regex:  p.Regex,
			action: p.Action,
		}
	}

	for _, pack := range packs {
		if len(pack.RuleIDs) == 0 {
			continue
		}

		matchedCount := 0
		var packOverrides []policy.RuleOverride

		for _, ruleID := range pack.RuleIDs {
			rule, found := ruleByID[ruleID]
			if !found {
				continue
			}

			for _, t := range trackers {
				if t.name == rule.Name || t.regex == rule.Regex {
					matchedCount++
					t.used = true
					if t.action != "" && policy.Action(t.action) != rule.DefaultAction {
						packOverrides = append(packOverrides, policy.RuleOverride{
							RuleID:  rule.ID,
							Action:  policy.Action(t.action),
							Enabled: true,
						})
					}
					break
				}
			}
		}

		if matchedCount > 0 && matchedCount >= (len(pack.RuleIDs)+1)/2 {
			cfg.PackIDs = append(cfg.PackIDs, pack.ID)
			cfg.Overrides = append(cfg.Overrides, packOverrides...)
		}
	}

	for _, t := range trackers {
		if !t.used {
			cfg.CustomPatterns = append(cfg.CustomPatterns, policy.CustomPattern{
				Name:   t.name,
				Regex:  t.regex,
				Action: policy.Action(t.action),
			})
		}
	}

	_ = store.SaveAgentConfig(ctx, cfg)
	return cfg
}
