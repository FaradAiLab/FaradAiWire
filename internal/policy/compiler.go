package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// RawPatternJSON matches the JSON schema expected by internal/filter/dlp/provider.go.
type RawPatternJSON struct {
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Action string `json:"action"`
}

// CompiledDLPPayload represents the JSON structure written to agents/<name>/current/dlp.json.
type CompiledDLPPayload struct {
	Enabled        bool                     `json:"enabled"`
	Patterns       []RawPatternJSON         `json:"patterns"`
	ToolExemptions map[string]ToolExemption `json:"tool_exemptions,omitempty"`
}

// EffectiveRule represents a resolved rule with inheritance, collision resolution, and agent override status.
type EffectiveRule struct {
	RuleID          string   `json:"rule_id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Category        string   `json:"category"`
	Regex           string   `json:"regex"`
	DefaultAction   Action   `json:"default_action"`
	ResolvedAction  Action   `json:"resolved_action"`
	EffectiveAction Action   `json:"effective_action"`
	IsBypassed      bool     `json:"is_bypassed"`
	IsOverridden    bool     `json:"is_overridden"`
	SourcePackIDs   []string `json:"source_pack_ids"`
}

// CompiledAgentPolicy represents the full compiled resolution for an agent.
type CompiledAgentPolicy struct {
	AgentName      string                   `json:"agent_name"`
	Enabled        bool                     `json:"enabled"`
	EffectiveRules []EffectiveRule          `json:"effective_rules"`
	CustomPatterns []CustomPattern          `json:"custom_patterns"`
	ToolExemptions map[string]ToolExemption `json:"tool_exemptions"`
}

// Compiler manages multi-pack inheritance resolution, conflict precedence,
// agent overrides, atomic filesystem emission, and runtime cache invalidation.
type Compiler struct {
	store     Store
	agentsDir string
	reloader  dlp.Reloader
	mu        sync.RWMutex
}

// CompilerOption configures optional behaviors of the Compiler.
type CompilerOption func(*Compiler)

// WithAgentsDir overrides the base agents directory (defaults to "./agents").
func WithAgentsDir(dir string) CompilerOption {
	return func(c *Compiler) {
		c.agentsDir = dir
	}
}

// WithReloader injects a Reloader (such as *dlp.AgentFileProvider) for runtime cache invalidation.
func WithReloader(reloader dlp.Reloader) CompilerOption {
	return func(c *Compiler) {
		c.reloader = reloader
	}
}

// NewCompiler creates a Compiler backed by the provided Store and options.
func NewCompiler(store Store, opts ...CompilerOption) *Compiler {
	c := &Compiler{
		store:     store,
		agentsDir: "./agents",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AgentsDir returns the base directory where agent policies are compiled.
func (c *Compiler) AgentsDir() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.agentsDir
}

type ruleAccumulator struct {
	rule          DlpPatternRule
	sourcePacks   []string
	winningAction Action
}

// Compile resolves the effective policy for an agent based on its configuration,
// attached packs, collision precedence (BLOCK > MASK > AUDIT), and overrides.
func (c *Compiler) Compile(ctx context.Context, cfg *AgentPolicyConfig) (*CompiledAgentPolicy, error) {
	if cfg == nil {
		return nil, errors.New("agent policy configuration cannot be nil")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. Gather all rules from attached packs
	accumulated := make(map[string]*ruleAccumulator)
	for _, packID := range cfg.PackIDs {
		pack, err := c.store.GetPack(ctx, packID)
		if err != nil {
			if errors.Is(err, ErrPackNotFound) {
				continue
			}
			return nil, fmt.Errorf("compile: get pack %s: %w", packID, err)
		}

		for _, r := range pack.Rules {
			existing, exists := accumulated[r.ID]
			if !exists {
				accumulated[r.ID] = &ruleAccumulator{
					rule:          r,
					sourcePacks:   []string{pack.ID},
					winningAction: r.DefaultAction,
				}
			} else {
				existing.sourcePacks = append(existing.sourcePacks, pack.ID)
				// Precedence rule: Most-Restrictive Action Wins (BLOCK > MASK > AUDIT)
				existing.winningAction = MostRestrictiveAction(existing.winningAction, r.DefaultAction)
			}
		}
	}

	// 2. Build override lookup map
	overrideMap := make(map[string]RuleOverride, len(cfg.Overrides))
	for _, o := range cfg.Overrides {
		overrideMap[o.RuleID] = o
	}

	// 3. Resolve effective rules
	effectiveRules := make([]EffectiveRule, 0, len(accumulated))
	for _, acc := range accumulated {
		eff := EffectiveRule{
			RuleID:          acc.rule.ID,
			Name:            acc.rule.Name,
			Description:     acc.rule.Description,
			Category:        acc.rule.Category,
			Regex:           acc.rule.Regex,
			DefaultAction:   acc.rule.DefaultAction,
			ResolvedAction:  acc.winningAction,
			EffectiveAction: acc.winningAction,
			IsBypassed:      false,
			IsOverridden:    false,
			SourcePackIDs:   acc.sourcePacks,
		}

		if ov, hasOverride := overrideMap[acc.rule.ID]; hasOverride {
			if !ov.Enabled {
				eff.IsBypassed = true
			}
			if ov.Action != "" && IsValidAction(ov.Action) {
				eff.EffectiveAction = ov.Action
				eff.IsOverridden = true
			}
		}

		effectiveRules = append(effectiveRules, eff)
	}

	// Deterministic sorting by Rule Name
	sort.Slice(effectiveRules, func(i, j int) bool {
		return effectiveRules[i].Name < effectiveRules[j].Name
	})

	// 4. Validate custom patterns
	for _, cp := range cfg.CustomPatterns {
		if _, err := regexp.Compile(cp.Regex); err != nil {
			return nil, fmt.Errorf("compile: invalid custom pattern %q: %w", cp.Name, err)
		}
	}

	// 5. Tool exemptions normalization
	toolExemptions := make(map[string]ToolExemption, len(cfg.ToolExemptions))
	for t, ex := range cfg.ToolExemptions {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			toolExemptions[trimmed] = ex
		}
	}

	return &CompiledAgentPolicy{
		AgentName:      cfg.AgentName,
		Enabled:        true,
		EffectiveRules: effectiveRules,
		CustomPatterns: cfg.CustomPatterns,
		ToolExemptions: toolExemptions,
	}, nil
}

// EmitPayload generates the CompiledDLPPayload ready for writing to dlp.json.
// Bypassed rules are excluded. Custom patterns are appended.
func (c *Compiler) EmitPayload(compiled *CompiledAgentPolicy) (*CompiledDLPPayload, error) {
	if compiled == nil {
		return nil, errors.New("compiled agent policy cannot be nil")
	}

	patterns := make([]RawPatternJSON, 0, len(compiled.EffectiveRules)+len(compiled.CustomPatterns))

	// Add non-bypassed inherited rules
	for _, r := range compiled.EffectiveRules {
		if r.IsBypassed {
			continue
		}
		patterns = append(patterns, RawPatternJSON{
			Name:   r.Name,
			Regex:  r.Regex,
			Action: string(r.EffectiveAction),
		})
	}

	// Add agent custom patterns
	for _, cp := range compiled.CustomPatterns {
		patterns = append(patterns, RawPatternJSON{
			Name:   cp.Name,
			Regex:  cp.Regex,
			Action: string(cp.Action),
		})
	}

	return &CompiledDLPPayload{
		Enabled:        compiled.Enabled,
		Patterns:       patterns,
		ToolExemptions: compiled.ToolExemptions,
	}, nil
}

// EmitJSON serializes the CompiledDLPPayload to formatted JSON bytes.
func (c *Compiler) EmitJSON(compiled *CompiledAgentPolicy) ([]byte, error) {
	payload, err := c.EmitPayload(compiled)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal dlp payload: %w", err)
	}
	return data, nil
}

// CompileAndSave compiles an agent's policy from the store, atomically writes
// the result to agents/<name>/current/dlp.json, and notifies the reloader.
func (c *Compiler) CompileAndSave(ctx context.Context, agentName string) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("validate agent identifier: %w", err)
	}

	cfg, err := c.store.GetAgentConfig(ctx, agentName)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			// If no config in store, emit an empty enabled=false configuration
			cfg = &AgentPolicyConfig{
				AgentName: agentName,
			}
		} else {
			return fmt.Errorf("get agent config %s: %w", agentName, err)
		}
	}

	compiled, err := c.Compile(ctx, cfg)
	if err != nil {
		return fmt.Errorf("compile policy for %s: %w", agentName, err)
	}

	jsonData, err := c.EmitJSON(compiled)
	if err != nil {
		return fmt.Errorf("emit json for %s: %w", agentName, err)
	}

	// Atomic write to agents/<name>/current/dlp.json
	currentDir := filepath.Join(c.agentsDir, agentName, "current")
	if err := os.MkdirAll(currentDir, 0750); err != nil {
		return fmt.Errorf("create current dir for %s: %w", agentName, err)
	}

	targetPath := filepath.Join(currentDir, "dlp.json")
	tmpPath := filepath.Join(currentDir, fmt.Sprintf("dlp.%d.tmp", time.Now().UnixNano()))

	if err := os.WriteFile(tmpPath, jsonData, 0644); err != nil {
		return fmt.Errorf("write temp dlp file %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename %s to %s: %w", tmpPath, targetPath, err)
	}

	// Invalidate runtime provider cache
	if c.reloader != nil {
		c.reloader.Reload(agentName)
	}

	return nil
}

// SaveConfigAndCompile saves the agent policy configuration to the store,
// then compiles and writes it to disk and triggers reload.
func (c *Compiler) SaveConfigAndCompile(ctx context.Context, cfg *AgentPolicyConfig) error {
	if err := c.store.SaveAgentConfig(ctx, cfg); err != nil {
		return fmt.Errorf("save agent config: %w", err)
	}
	return c.CompileAndSave(ctx, cfg.AgentName)
}

// PropagatePackUpdate recompiles and reloads all agents that inherit the updated pack.
func (c *Compiler) PropagatePackUpdate(ctx context.Context, packID string) ([]string, error) {
	agents, err := c.store.ListAgentsUsingPack(ctx, packID)
	if err != nil {
		return nil, fmt.Errorf("list agents using pack %s: %w", packID, err)
	}

	recompiled := make([]string, 0, len(agents))
	for _, agentName := range agents {
		if err := c.CompileAndSave(ctx, agentName); err != nil {
			return recompiled, fmt.Errorf("propagate pack update to agent %s: %w", agentName, err)
		}
		recompiled = append(recompiled, agentName)
	}

	return recompiled, nil
}
