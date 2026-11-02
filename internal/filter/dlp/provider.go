package dlp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
)

// rawToolExemptionJSON maps directional exemptions in dlp.json files.
type rawToolExemptionJSON struct {
	Request  bool `json:"request"`
	Response bool `json:"response"`
}

// agentDLPPayload represents the JSON schema of dlp.json configuration files.
type agentDLPPayload struct {
	Enabled        bool                            `json:"enabled"`
	CustomPatterns []rawPatternJSON                `json:"custom_patterns"`
	Patterns       []rawPatternJSON                `json:"patterns"`
	ToolExemptions map[string]rawToolExemptionJSON `json:"tool_exemptions,omitempty"`
}

type rawPatternJSON struct {
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Action string `json:"action"`
}

type agentDLPConfig struct {
	enabled        bool
	patterns       []CompiledPattern
	toolExemptions map[string]DirectionFlags
	mtime          time.Time
}

// AgentFileProvider resolves DLP rules from agent-scoped dlp.json files,
// falling back to baseline rules when no agent override is specified.
type AgentFileProvider struct {
	baselineEnabled    bool
	baselineExemptions map[string]DirectionFlags
	baselinePatterns   []CompiledPattern
	agentsDir          string

	mu           sync.RWMutex
	agentConfigs map[string]*agentDLPConfig
}

// NewAgentFileProvider constructs an AgentFileProvider with global baseline rules.
func NewAgentFileProvider(
	baselineEnabled bool,
	baselineExclude []string,
	baselinePatterns []CompiledPattern,
	agentsDir string,
) *AgentFileProvider {
	baselineExemptions := make(map[string]DirectionFlags, len(baselineExclude))
	for _, t := range baselineExclude {
		baselineExemptions[t] = FlagExemptRequest | FlagExemptResponse
	}
	return &AgentFileProvider{
		baselineEnabled:    baselineEnabled,
		baselineExemptions: baselineExemptions,
		baselinePatterns:   baselinePatterns,
		agentsDir:          agentsDir,
		agentConfigs:       make(map[string]*agentDLPConfig),
	}
}

// ResolveRules returns the effective RuleSet for the current execution context.
// Follows ADR-0022 precedence: agent-level override takes precedence over baseline.
func (p *AgentFileProvider) ResolveRules(ctx context.Context) RuleSet {
	agentName := extractAgentName(ctx)
	if agentName != "" {
		if cfg := p.getAgentConfig(agentName); cfg != nil {
			if !cfg.enabled {
				// Clean bypass (ADR-0022): disabled at agent level means no DLP
				return RuleSet{Enabled: false}
			}
			return RuleSet{
				Enabled:        true,
				Patterns:       cfg.patterns,
				ToolExemptions: cfg.toolExemptions,
			}
		}
	}

	return RuleSet{
		Enabled:        p.baselineEnabled,
		Patterns:       p.baselinePatterns,
		ToolExemptions: p.baselineExemptions,
	}
}

// Reload forces reloading the agent configuration from disk and atomically swaps the cache.
// Event-driven per ADR-0048 Decision 3: called when policy compiler or file watcher signals changes.
func (p *AgentFileProvider) Reload(agentName string) {
	dlpPath := p.resolveAgentDLPPath(agentName)
	if dlpPath == "" {
		p.mu.Lock()
		p.agentConfigs[agentName] = nil
		p.mu.Unlock()
		return
	}

	stat, err := os.Stat(dlpPath)
	if err != nil {
		p.mu.Lock()
		p.agentConfigs[agentName] = nil
		p.mu.Unlock()
		return
	}

	newCfg, err := p.loadAndCompile(dlpPath)
	if err != nil {
		slog.Warn("Failed to reload agent dlp.json, retaining LKG cache",
			slog.String("agent", agentName),
			slog.String("path", dlpPath),
			slog.String("error", err.Error()),
		)
		// Retain Last-Known-Good configuration on compilation/syntax error
		return
	}

	newCfg.mtime = stat.ModTime()

	p.mu.Lock()
	p.agentConfigs[agentName] = newCfg
	p.mu.Unlock()

	slog.Info("Reloaded agent-specific DLP rules",
		slog.String("agent", agentName),
		slog.Bool("enabled", newCfg.enabled),
		slog.Int("patterns", len(newCfg.patterns)),
		slog.String("path", dlpPath),
	)
}

// getAgentConfig retrieves the compiled DLP configuration for an agent.
// Zero-I/O hot-path: returns directly from in-memory cache under RLock.
// On cache miss, resolves from disk, compiles, and caches (including negative cache).
func (p *AgentFileProvider) getAgentConfig(agentName string) *agentDLPConfig {
	p.mu.RLock()
	cached, exists := p.agentConfigs[agentName]
	p.mu.RUnlock()

	if exists {
		return cached
	}

	// Cold path (first access or after eviction): read and compile without holding lock across I/O
	newCfg := p.loadAgentConfigFromDisk(agentName)

	p.mu.Lock()
	if existing, ok := p.agentConfigs[agentName]; ok {
		p.mu.Unlock()
		return existing
	}
	p.agentConfigs[agentName] = newCfg
	p.mu.Unlock()

	return newCfg
}

func (p *AgentFileProvider) loadAgentConfigFromDisk(agentName string) *agentDLPConfig {
	dlpPath := p.resolveAgentDLPPath(agentName)
	if dlpPath == "" {
		return nil
	}

	stat, err := os.Stat(dlpPath)
	if err != nil {
		return nil
	}

	newCfg, err := p.loadAndCompile(dlpPath)
	if err != nil {
		slog.Warn("Failed to load agent dlp.json",
			slog.String("agent", agentName),
			slog.String("path", dlpPath),
			slog.String("error", err.Error()),
		)
		return nil
	}

	newCfg.mtime = stat.ModTime()

	slog.Info("Loaded agent-specific DLP rules",
		slog.String("agent", agentName),
		slog.Bool("enabled", newCfg.enabled),
		slog.Int("patterns", len(newCfg.patterns)),
		slog.String("path", dlpPath),
	)

	return newCfg
}

func (p *AgentFileProvider) loadAndCompile(path string) (*agentDLPConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dlp file: %w", err)
	}

	var payload agentDLPPayload
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil, fmt.Errorf("parse dlp json: %w", err)
	}

	rawPatterns := payload.Patterns
	if len(rawPatterns) == 0 {
		rawPatterns = payload.CustomPatterns
	}

	compiled := make([]CompiledPattern, 0, len(rawPatterns))
	for _, raw := range rawPatterns {
		if raw.Regex == "" {
			continue
		}
		re, err := regexp.Compile(raw.Regex)
		if err != nil {
			return nil, fmt.Errorf("compile regex for %q: %w", raw.Name, err)
		}
		action := Action(raw.Action)
		if action == "" {
			action = ActionMask
		}
		compiled = append(compiled, CompiledPattern{
			Name:   raw.Name,
			Regex:  re,
			Action: action,
		})
	}

	toolExemptions := make(map[string]DirectionFlags, len(payload.ToolExemptions))
	for toolName, ex := range payload.ToolExemptions {
		var flags DirectionFlags
		if ex.Request {
			flags |= FlagExemptRequest
		}
		if ex.Response {
			flags |= FlagExemptResponse
		}
		toolExemptions[toolName] = flags
	}

	return &agentDLPConfig{
		enabled:        payload.Enabled,
		patterns:       compiled,
		toolExemptions: toolExemptions,
	}, nil
}

func (p *AgentFileProvider) resolveAgentDLPPath(agentName string) string {
	if agentName == "" || strings.Contains(agentName, "..") || filepath.IsAbs(agentName) {
		return ""
	}
	var candidates []string
	if p.agentsDir != "" {
		candidates = append(candidates,
			filepath.Join(p.agentsDir, agentName, "current", "dlp.json"),
			filepath.Join(p.agentsDir, agentName, "dlp.json"),
		)
	}
	candidates = append(candidates,
		filepath.Join("/etc/faradaiwire/agents", agentName, "current", "dlp.json"),
		filepath.Join("/etc/faradaiwire/agents", agentName, "dlp.json"),
		filepath.Join("./agents", agentName, "current", "dlp.json"),
		filepath.Join("./agents", agentName, "dlp.json"),
	)

	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func extractAgentName(ctx context.Context) string {
	keys := []any{types.AgentNameContextKey, "agent", "agent_name"}
	for _, k := range keys {
		if val := ctx.Value(k); val != nil {
			if s, ok := val.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
