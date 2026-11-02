package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

// handleAgentDLP handles reading and saving DLP governance configurations for a specific agent:
//   GET /admin/agents/{name}/dlp -> Get saved config and compiled effective preview
//   PUT /admin/agents/{name}/dlp -> Save config, atomically compile to dlp.json, and hot-reload
func (a *AdminServer) handleAgentDLP(w http.ResponseWriter, r *http.Request, agentName string) {
	w.Header().Set("Content-Type", "application/json")

	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_AGENT_IDENTIFIER",
			"message": err.Error(),
		})
		return
	}

	store := a.getPolicyStore()
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "POLICY_STORE_UNAVAILABLE",
			"message": "Policy store is not initialized",
		})
		return
	}

	compiler := a.getPolicyCompiler()

	switch r.Method {
	case http.MethodGet:
		cfg, err := store.GetAgentConfig(r.Context(), agentName)
		if err != nil {
			if errors.Is(err, policy.ErrConfigNotFound) {
				// Reconcile from existing agents/<agentName>/current/dlp.json if present on disk
				if recCfg := a.reconcileAgentDLPFromDisk(r.Context(), agentName, store); recCfg != nil {
					cfg = recCfg
				} else {
					// Return clean empty configuration
					cfg = &policy.AgentPolicyConfig{
						AgentName:      agentName,
						PackIDs:        []string{},
						Overrides:      []policy.RuleOverride{},
						CustomPatterns: []policy.CustomPattern{},
						ToolExemptions: make(map[string]policy.ToolExemption),
					}
				}
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "GET_AGENT_CONFIG_FAILED",
					"message": err.Error(),
				})
				return
			}
		}

		var compiled *policy.CompiledAgentPolicy
		if compiler != nil {
			comp, cErr := compiler.Compile(r.Context(), cfg)
			if cErr == nil {
				compiled = comp
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_name": agentName,
			"config":     cfg,
			"compiled":   compiled,
		})
		return

	case http.MethodPut:
		if a.cfg != nil && a.cfg.IsManaged() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Agent policy editing is locked: Gateway is managed by organization.",
			})
			return
		}

		var cfg policy.AgentPolicyConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_JSON",
				"message": "Failed to decode agent DLP config: " + err.Error(),
			})
			return
		}
		cfg.AgentName = agentName

		if err := policy.ValidateAgentPolicyConfig(&cfg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "VALIDATION_FAILED",
				"message": err.Error(),
			})
			return
		}

		// Enforce atomic rollback parity: snapshot current agent state before updating DLP
		if repo := a.getAgentRepository(); repo != nil {
			if err := repo.ArchiveAgentCurrent(agentName); err != nil {
				slog.WarnContext(r.Context(), "Failed to create agent snapshot archive before saving DLP", "agent", agentName, "error", err)
			}
		}

		if compiler != nil {
			if err := compiler.SaveConfigAndCompile(r.Context(), &cfg); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "COMPILE_AND_SAVE_FAILED",
					"message": err.Error(),
				})
				return
			}
		} else {
			if err := store.SaveAgentConfig(r.Context(), &cfg); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "SAVE_AGENT_CONFIG_FAILED",
					"message": err.Error(),
				})
				return
			}
		}

		var compiled *policy.CompiledAgentPolicy
		if compiler != nil {
			compiled, _ = compiler.Compile(r.Context(), &cfg)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "saved",
			"agent_name": agentName,
			"config":     cfg,
			"compiled":   compiled,
		})
		return

	default:
		w.Header().Set("Allow", "GET, PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET and PUT methods are supported on /admin/agents/{name}/dlp",
		})
		return
	}
}

// reconcileAgentDLPFromDisk attempts to reconstruct an AgentPolicyConfig from an existing
// agents/<name>/current/dlp.json file when DuckDB lacks an agent_dlp_configs entry.
func (a *AdminServer) reconcileAgentDLPFromDisk(ctx context.Context, agentName string, store policy.Store) *policy.AgentPolicyConfig {
	agentsDir := a.getAgentsDir()
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

