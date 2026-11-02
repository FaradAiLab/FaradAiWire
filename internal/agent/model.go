package agent

import (
	"encoding/json"
	"strings"
)

// ProtocolConfig represents an upstream Model Context Protocol backend endpoint (stdio subprocess or HTTP/SSE gateway).
type ProtocolConfig struct {
	ID           string   `json:"protocol_id"`
	Name         string   `json:"protocol_name"`
	Type         string   `json:"type"` // "stdio", "sse", "http"
	URLOrCommand string   `json:"url_or_command"`
	Command      string   `json:"command,omitempty"`
	Args         []string `json:"args,omitempty"`
	Env          []string `json:"env,omitempty"`
	AuthToken    string            `json:"auth_token,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	TargetScope  string            `json:"target_scope,omitempty"` // "local" or "corporate" / "upstream"
	AllowedTools []string `json:"allowed_tools,omitempty"`
}

// IsToolAllowed returns true if toolName is permitted under the protocol's allowed_tools whitelist.
// If AllowedTools is empty or nil, all tools are permitted by default.
func (p *ProtocolConfig) IsToolAllowed(toolName string) bool {
	if p == nil || len(p.AllowedTools) == 0 {
		return true
	}
	cleanName := toolName
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		cleanName = parts[1]
	}
	for _, allowed := range p.AllowedTools {
		if strings.EqualFold(allowed, toolName) || strings.EqualFold(allowed, cleanName) {
			return true
		}
	}
	return false
}

// IsStdio returns true if the protocol executes a local subprocess via stdin/stdout.
func (p *ProtocolConfig) IsStdio() bool {
	if p == nil {
		return false
	}
	if strings.EqualFold(p.Type, "stdio") {
		return true
	}
	if p.Type == "" && p.URLOrCommand != "" {
		lower := strings.ToLower(p.URLOrCommand)
		return !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://")
	}
	return false
}

// IsStreamableHTTP returns true if the protocol uses Streamable HTTP (direct JSON-RPC POST) transport.
func (p *ProtocolConfig) IsStreamableHTTP() bool {
	if p == nil {
		return false
	}
	return strings.EqualFold(p.Type, "http") || strings.EqualFold(p.Type, "streamable_http")
}

// IsCorporate returns true if the protocol targets an upstream enterprise gateway.
func (p *ProtocolConfig) IsCorporate() bool {
	if p == nil {
		return false
	}
	scope := strings.ToLower(strings.TrimSpace(p.TargetScope))
	return scope == "corporate" || scope == "upstream" || scope == "enterprise"
}

// GetCommand returns the executable command for stdio protocols.
func (p *ProtocolConfig) GetCommand() string {
	if p.Command != "" {
		return p.Command
	}
	return p.URLOrCommand
}

// Clone returns a deep copy of ProtocolConfig.
func (p ProtocolConfig) Clone() ProtocolConfig {
	cp := p
	if p.Args != nil {
		cp.Args = append([]string(nil), p.Args...)
	}
	if p.Env != nil {
		cp.Env = append([]string(nil), p.Env...)
	}
	if p.AllowedTools != nil {
		cp.AllowedTools = append([]string(nil), p.AllowedTools...)
	}
	if p.Headers != nil {
		cp.Headers = make(map[string]string, len(p.Headers))
		for k, v := range p.Headers {
			cp.Headers[k] = v
		}
	}
	return cp
}

// UnmarshalJSON provides flexible backward-compatible deserialization for both protocol_id/id and protocol_name/name.
func (p *ProtocolConfig) UnmarshalJSON(data []byte) error {
	type Alias ProtocolConfig
	aux := struct {
		AltID   string `json:"id"`
		AltName string `json:"name"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if p.ID == "" && aux.AltID != "" {
		p.ID = aux.AltID
	}
	if p.Name == "" && aux.AltName != "" {
		p.Name = aux.AltName
	}
	return nil
}

// ToolGovernanceMode represents the operational security & human-in-the-loop policy for an agent tool.
type ToolGovernanceMode string

const (
	// ModeAutonomous bypasses L2 SLM neural inspection and HITL gates (<0.2ms fast path).
	ModeAutonomous ToolGovernanceMode = "autonomous"
	// ModeGuardedBlock inspects via L2 SLM; auto-blocks threat verdicts with -32004 without human prompting.
	ModeGuardedBlock ToolGovernanceMode = "guarded_block"
	// ModeGuardedHITL inspects via L2 SLM; safe executions pass, while threats escalate to dual-channel HITL approval.
	ModeGuardedHITL ToolGovernanceMode = "guarded_hitl"
	// ModeStrictAlwaysHITL unconditionally pauses execution and requests dual-channel human approval before every call.
	ModeStrictAlwaysHITL ToolGovernanceMode = "strict_always_hitl"
)

// IsValid reports whether m is one of the four recognized ToolGovernanceMode values.
func (m ToolGovernanceMode) IsValid() bool {
	switch m {
	case ModeAutonomous, ModeGuardedBlock, ModeGuardedHITL, ModeStrictAlwaysHITL:
		return true
	default:
		return false
	}
}

// ToolOverrides specifies granular agent-level allow rules for exposed tools.
type ToolOverrides struct {
	EnabledTools []string `json:"enabled_tools,omitempty"`
}

// RateLimitOverride configures token-bucket rate limits for an individual agent (ADR-0042).
type RateLimitOverride struct {
	MaxBurst   int     `json:"max_burst"`
	RefillRate float64 `json:"refill_rate"`
}

// LoopProtectionOverride configures infinite reasoning loop detection for an individual agent (ADR-0042).
type LoopProtectionOverride struct {
	Enabled       bool     `json:"enabled"`
	MaxRepeat     int      `json:"max_repeat"`
	WindowSeconds int      `json:"window_seconds"`
	ExcludeTools  []string `json:"exclude_tools,omitempty"`
}

// RouteConfig represents an agent's routing policy and attached MCP protocols.
type RouteConfig struct {
	AgentID            string                                   `json:"agent_id"`
	AgentName          string                                   `json:"agent_name"`
	Description        string                                   `json:"description"`
	RoutingMode        string                                   `json:"routing_mode"` // "aggregated" (default) or "direct"
	Protocols          []ProtocolConfig                         `json:"protocols"`
	EnabledTools       []string                                 `json:"enabled_tools,omitempty"`       // Layer 2 scoping whitelist
	ToolOverrides      *ToolOverrides                           `json:"tool_overrides,omitempty"`     // Layer 2 scoping overrides
	ToolGovernance     map[string]ToolGovernanceMode            `json:"tool_governance,omitempty"`     // Layer 3 tool governance & HITL matrix
	RetainedGovernance map[string]map[string]ToolGovernanceMode `json:"retained_governance,omitempty"` // Layer 3 configuration retention per detached protocol
	RateLimit          *RateLimitOverride                       `json:"rate_limit,omitempty"`          // Agent-level Rate Limiting override (ADR-0042)
	LoopProtection     *LoopProtectionOverride                  `json:"loop_protection,omitempty"`     // Agent-level Loop Protection override (ADR-0042)
}

// UnmarshalJSON provides flexible unmarshaling for agent_name/name and sets default routing mode.
func (r *RouteConfig) UnmarshalJSON(data []byte) error {
	type Alias RouteConfig
	aux := struct {
		AltName string `json:"name"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if r.AgentName == "" && aux.AltName != "" {
		r.AgentName = aux.AltName
	}
	if r.RoutingMode == "" {
		r.RoutingMode = "aggregated"
	}
	return nil
}

// Clone returns a deep copy of RouteConfig, ensuring all slices and nested maps are independent.
func (r *RouteConfig) Clone() *RouteConfig {
	if r == nil {
		return nil
	}
	clone := &RouteConfig{
		AgentID:     r.AgentID,
		AgentName:   r.AgentName,
		Description: r.Description,
		RoutingMode: r.RoutingMode,
	}

	if r.Protocols != nil {
		clone.Protocols = make([]ProtocolConfig, len(r.Protocols))
		for i, p := range r.Protocols {
			clone.Protocols[i] = p.Clone()
		}
	}

	if r.EnabledTools != nil {
		clone.EnabledTools = append([]string(nil), r.EnabledTools...)
	}

	if r.ToolOverrides != nil {
		clone.ToolOverrides = &ToolOverrides{}
		if r.ToolOverrides.EnabledTools != nil {
			clone.ToolOverrides.EnabledTools = append([]string(nil), r.ToolOverrides.EnabledTools...)
		}
	}

	if r.ToolGovernance != nil {
		clone.ToolGovernance = make(map[string]ToolGovernanceMode, len(r.ToolGovernance))
		for k, v := range r.ToolGovernance {
			clone.ToolGovernance[k] = v
		}
	}

	if r.RetainedGovernance != nil {
		clone.RetainedGovernance = make(map[string]map[string]ToolGovernanceMode, len(r.RetainedGovernance))
		for k, v := range r.RetainedGovernance {
			if v != nil {
				inner := make(map[string]ToolGovernanceMode, len(v))
				for ik, iv := range v {
					inner[ik] = iv
				}
				clone.RetainedGovernance[k] = inner
			} else {
				clone.RetainedGovernance[k] = nil
			}
		}
	}

	if r.RateLimit != nil {
		clone.RateLimit = &RateLimitOverride{
			MaxBurst:   r.RateLimit.MaxBurst,
			RefillRate: r.RateLimit.RefillRate,
		}
	}

	if r.LoopProtection != nil {
		clone.LoopProtection = &LoopProtectionOverride{
			Enabled:       r.LoopProtection.Enabled,
			MaxRepeat:     r.LoopProtection.MaxRepeat,
			WindowSeconds: r.LoopProtection.WindowSeconds,
		}
		if r.LoopProtection.ExcludeTools != nil {
			clone.LoopProtection.ExcludeTools = append([]string(nil), r.LoopProtection.ExcludeTools...)
		}
	}

	return clone
}

// ToolMetadata describes an individual tool within an agent's tools_manifest.json.
type ToolMetadata struct {
	Name          string                 `json:"name"`
	RawName       string                 `json:"raw_name,omitempty"`
	CanonicalName string                 `json:"canonical_name,omitempty"`
	ProtocolName  string                 `json:"protocol_name"`
	ProtocolID    string                 `json:"protocol_id,omitempty"`
	Description   string                 `json:"description,omitempty"`
	InputSchema   map[string]interface{} `json:"inputSchema,omitempty"`
}

// ToolTargetInfo contains resolved target MCP routing details for executing a specific tool.
type ToolTargetInfo struct {
	ProtocolID   string   `json:"protocol_id"`
	ProtocolName string   `json:"protocol_name"`
	TargetURL    string   `json:"target_url"`
	ToolName     string   `json:"tool_name"`
	RawToolName  string   `json:"raw_tool_name,omitempty"`
	Type         string   `json:"type"` // "stdio", "sse", "http"
	Command      string   `json:"command,omitempty"`
	Args         []string `json:"args,omitempty"`
	Env          []string `json:"env,omitempty"`
	AuthToken    string            `json:"auth_token,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	TargetScope  string            `json:"target_scope,omitempty"` // "local" or "corporate" / "upstream"
	AllowedTools []string `json:"allowed_tools,omitempty"`
}

// IsToolAllowed returns true if toolName is permitted under the resolved target's allowed_tools whitelist.
func (t *ToolTargetInfo) IsToolAllowed(toolName string) bool {
	if t == nil || len(t.AllowedTools) == 0 {
		return true
	}
	cleanName := toolName
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		cleanName = parts[1]
	}
	for _, allowed := range t.AllowedTools {
		if strings.EqualFold(allowed, toolName) || strings.EqualFold(allowed, cleanName) {
			return true
		}
	}
	return false
}

// IsStdio returns true if the tool target executes via local stdio subprocess.
func (t *ToolTargetInfo) IsStdio() bool {
	if t == nil {
		return false
	}
	if strings.EqualFold(t.Type, "stdio") {
		return true
	}
	if t.Type == "" && t.Command != "" {
		return true
	}
	if t.Type == "" && t.TargetURL != "" {
		lower := strings.ToLower(t.TargetURL)
		return !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://")
	}
	return false
}

// IsStreamableHTTP returns true if the tool target uses Streamable HTTP (direct JSON-RPC POST) transport.
func (t *ToolTargetInfo) IsStreamableHTTP() bool {
	if t == nil {
		return false
	}
	return strings.EqualFold(t.Type, "http") || strings.EqualFold(t.Type, "streamable_http")
}

// IsCorporate returns true if the tool target routes to an upstream corporate gateway.
func (t *ToolTargetInfo) IsCorporate() bool {
	if t == nil {
		return false
	}
	scope := strings.ToLower(strings.TrimSpace(t.TargetScope))
	return scope == "corporate" || scope == "upstream" || scope == "enterprise"
}

// IsAggregated returns true if the agent is configured in aggregated multi-protocol ingress mode.
func (r *RouteConfig) IsAggregated() bool {
	return strings.EqualFold(r.RoutingMode, "aggregated") || r.RoutingMode == ""
}

// IsDirect returns true if the agent is configured in direct 1-to-1 ingress mode.
func (r *RouteConfig) IsDirect() bool {
	return strings.EqualFold(r.RoutingMode, "direct")
}

// GetProtocolSlug returns the clean slug/prefix for an MCP protocol.
func GetProtocolSlug(proto *ProtocolConfig) string {
	if proto == nil {
		return ""
	}
	if proto.Name != "" && !strings.Contains(proto.Name, " ") && strings.HasSuffix(proto.ID, "-proto") {
		return strings.ToLower(proto.Name)
	}
	if proto.ID != "" && !strings.Contains(proto.ID, " ") {
		return strings.ToLower(proto.ID)
	}
	if proto.Name != "" {
		if !strings.Contains(proto.Name, " ") {
			return strings.ToLower(proto.Name)
		}
		if proto.ID != "" {
			return strings.ToLower(strings.ReplaceAll(proto.ID, " ", "_"))
		}
		return strings.ToLower(strings.ReplaceAll(proto.Name, " ", "_"))
	}
	return ""
}

// FindProtocol attempts to locate an attached protocol by ID or Name (case-insensitive) or protocol slug.
func (r *RouteConfig) FindProtocol(nameOrID string) *ProtocolConfig {
	if r == nil || nameOrID == "" {
		return nil
	}
	for i := range r.Protocols {
		slug := GetProtocolSlug(&r.Protocols[i])
		if strings.EqualFold(r.Protocols[i].Name, nameOrID) ||
			strings.EqualFold(r.Protocols[i].ID, nameOrID) ||
			(slug != "" && strings.EqualFold(slug, nameOrID)) {
			return &r.Protocols[i]
		}
	}
	return nil
}

// IsToolAllowed returns true if toolName is allowed under the agent's Layer 2 scoping rules.
// If neither EnabledTools nor ToolOverrides.EnabledTools is configured, all tools are permitted by default at Layer 2.
func (r *RouteConfig) IsToolAllowed(toolName string) bool {
	if r == nil {
		return true
	}
	cleanName := toolName
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		cleanName = parts[1]
	}

	// Resolve enabled list (from ToolOverrides.EnabledTools or EnabledTools)
	var enabledList []string
	if r.ToolOverrides != nil && len(r.ToolOverrides.EnabledTools) > 0 {
		enabledList = r.ToolOverrides.EnabledTools
	} else if len(r.EnabledTools) > 0 {
		enabledList = r.EnabledTools
	}

	if len(enabledList) == 0 {
		return true // No Layer 2 restriction
	}

	for _, allowed := range enabledList {
		if strings.EqualFold(allowed, toolName) || strings.EqualFold(allowed, cleanName) {
			return true
		}
	}
	return false
}

// GetToolGovernanceMode returns the configured ToolGovernanceMode for a tool, or fallback if unconfigured.
// It checks both the full (potentially namespaced) toolName and the clean un-prefixed tool name in O(1) time.
func (r *RouteConfig) GetToolGovernanceMode(toolName string) (ToolGovernanceMode, bool) {
	if r == nil || len(r.ToolGovernance) == 0 {
		return "", false
	}
	if mode, ok := r.ToolGovernance[toolName]; ok && mode.IsValid() {
		return mode, true
	}
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		if mode, ok := r.ToolGovernance[parts[1]]; ok && mode.IsValid() {
			return mode, true
		}
	}
	return "", false
}

// ComputeEffectiveTools computes the intersection of protocol whitelists and agent-level tool overrides.
func (r *RouteConfig) ComputeEffectiveTools(manifestTools []ToolMetadata) []ToolMetadata {
	if r == nil {
		return manifestTools
	}
	var effective []ToolMetadata
	for _, t := range manifestTools {
		// Layer 1: Protocol whitelist
		proto := r.FindProtocol(t.ProtocolID)
		if proto == nil {
			proto = r.FindProtocol(t.ProtocolName)
		}
		if proto != nil && len(proto.AllowedTools) > 0 {
			if !proto.IsToolAllowed(t.Name) && !proto.IsToolAllowed(t.RawName) && !proto.IsToolAllowed(t.CanonicalName) {
				continue
			}
		}
		// Layer 2: Agent tool scoping
		if !r.IsToolAllowed(t.Name) && !r.IsToolAllowed(t.RawName) && !r.IsToolAllowed(t.CanonicalName) {
			continue
		}
		effective = append(effective, t)
	}
	return effective
}


