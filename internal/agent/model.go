package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

// ProtocolConfig represents an upstream Model Context Protocol backend endpoint (stdio subprocess or HTTP/SSE gateway).
type ProtocolConfig struct {
	ID           string            `json:"protocol_id"`
	Name         string            `json:"protocol_name"`
	Type         string            `json:"type"` // "stdio", "sse", "http"
	URLOrCommand string            `json:"url_or_command"`
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	Env          []string          `json:"env,omitempty"`
	AuthToken    string            `json:"auth_token,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	TargetScope  string            `json:"target_scope,omitempty"` // "local" or "corporate" / "upstream"
	AllowedTools []string          `json:"allowed_tools,omitempty"`
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
	// ModeAutonomous bypasses L2 AI Guard neural inspection and HITL gates (<0.2ms fast path).
	ModeAutonomous ToolGovernanceMode = "autonomous"
	// ModeGuardedBlock inspects via L2 AI Guard; auto-blocks threat verdicts with -32004 without human prompting.
	ModeGuardedBlock ToolGovernanceMode = "guarded_block"
	// ModeGuardedHITL inspects via L2 AI Guard; safe executions pass, while threats escalate to dual-channel HITL approval.
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
	MaxRepeat     int      `json:"max_repeat"`
	WindowSeconds int      `json:"window_seconds"`
	ExcludeTools  []string `json:"exclude_tools,omitempty"`
}

// SchemaValidationMode defines per-agent enforcement behavior for SchemaFilter.
type SchemaValidationMode string

const (
	// SchemaValidationEnforce validates tool arguments strictly and blocks invalid calls (default).
	SchemaValidationEnforce SchemaValidationMode = "enforce"
	// SchemaValidationAudit records schema mismatches in AuditMetadata without blocking execution.
	SchemaValidationAudit SchemaValidationMode = "audit"
	// SchemaValidationOff bypasses schema validation for the agent profile.
	SchemaValidationOff SchemaValidationMode = "off"
)

// IsValid returns true when m is a supported SchemaValidationMode value.
func (m SchemaValidationMode) IsValid() bool {
	switch m {
	case SchemaValidationEnforce, SchemaValidationAudit, SchemaValidationOff:
		return true
	default:
		return false
	}
}

// SchemaValidationOverride configures schema validation governance for an individual agent.
type SchemaValidationOverride struct {
	Mode SchemaValidationMode `json:"mode"` // "enforce" (default), "audit", or "off"
}

// GuardEnforcementMode defines per-agent enforcement behavior for Semantic Security Guard.
type GuardEnforcementMode string

const (
	// GuardModeEnforce applies L1/L2 guard policies strictly (default).
	GuardModeEnforce GuardEnforcementMode = "enforce"
	// GuardModeAudit evaluates guard rules and records findings in AuditMetadata without blocking.
	GuardModeAudit GuardEnforcementMode = "audit"
	// GuardModeOff bypasses request L1 block and response guard blocking for the agent profile.
	GuardModeOff GuardEnforcementMode = "off"
)

// IsValid returns true when m is a supported GuardEnforcementMode value.
func (m GuardEnforcementMode) IsValid() bool {
	switch m {
	case GuardModeEnforce, GuardModeAudit, GuardModeOff:
		return true
	default:
		return false
	}
}

// GuardOverride configures Semantic Security Guard enforcement behavior for an individual agent.
type GuardOverride struct {
	Mode GuardEnforcementMode `json:"mode"` // "enforce" (default), "audit", or "off"
}

// RouteConfig represents an agent's routing policy and attached MCP protocols.
type RouteConfig struct {
	AgentID            string                                   `json:"agent_id"`
	AgentName          string                                   `json:"agent_name"`
	Description        string                                   `json:"description"`
	RoutingMode        string                                   `json:"routing_mode"` // "aggregated" (default) or "direct"
	Protocols          []ProtocolConfig                         `json:"protocols"`
	EnabledTools       []string                                 `json:"enabled_tools,omitempty"`       // Layer 2 scoping whitelist
	ToolOverrides      *ToolOverrides                           `json:"tool_overrides,omitempty"`      // Layer 2 scoping overrides
	ToolGovernance     map[string]ToolGovernanceMode            `json:"tool_governance,omitempty"`     // Layer 3 tool governance & HITL matrix
	RetainedGovernance map[string]map[string]ToolGovernanceMode `json:"retained_governance,omitempty"` // Layer 3 configuration retention per detached protocol
	RateLimit          *RateLimitOverride                       `json:"rate_limit,omitempty"`          // Agent-level Rate Limiting override (ADR-0042)
	LoopProtection     *LoopProtectionOverride                  `json:"loop_protection,omitempty"`     // Agent-level Loop Protection override (ADR-0042)
	SchemaValidation   *SchemaValidationOverride                `json:"schema_validation,omitempty"`   // Agent-level Schema Validation mode (SEC-023)
	Guard              *GuardOverride                           `json:"guard,omitempty"`               // Agent-level Semantic Security Guard mode (SEC-023)
}

// GetSchemaValidationMode resolves the effective SchemaValidationMode, defaulting to enforce.
func (r *RouteConfig) GetSchemaValidationMode() SchemaValidationMode {
	if r == nil || r.SchemaValidation == nil || !r.SchemaValidation.Mode.IsValid() {
		return SchemaValidationEnforce
	}
	return r.SchemaValidation.Mode
}

// GetGuardMode resolves the effective GuardEnforcementMode, defaulting to enforce.
func (r *RouteConfig) GetGuardMode() GuardEnforcementMode {
	if r == nil || r.Guard == nil || !r.Guard.Mode.IsValid() {
		return GuardModeEnforce
	}
	return r.Guard.Mode
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
			MaxRepeat:     r.LoopProtection.MaxRepeat,
			WindowSeconds: r.LoopProtection.WindowSeconds,
		}
		if r.LoopProtection.ExcludeTools != nil {
			clone.LoopProtection.ExcludeTools = append([]string(nil), r.LoopProtection.ExcludeTools...)
		}
	}

	if r.SchemaValidation != nil {
		clone.SchemaValidation = &SchemaValidationOverride{
			Mode: r.SchemaValidation.Mode,
		}
	}

	if r.Guard != nil {
		clone.Guard = &GuardOverride{
			Mode: r.Guard.Mode,
		}
	}

	return clone
}

// MaskSecrets returns a copy of ProtocolConfig with sensitive credentials masked for Admin API responses.
func (p ProtocolConfig) MaskSecrets() ProtocolConfig {
	cp := p.Clone()
	for i, envStr := range cp.Env {
		cp.Env[i] = protocol.MaskEnvString(envStr)
	}
	if cp.AuthToken != "" {
		cp.AuthToken = protocol.MaskSecretValue(cp.AuthToken)
	}
	for k, v := range cp.Headers {
		cp.Headers[k] = protocol.MaskHeaderValue(k, v)
	}
	cp.URLOrCommand = protocol.RedactURLCredentials(cp.URLOrCommand)
	return cp
}

// MaskSecrets returns a deep copy of RouteConfig safe for Admin API responses with embedded
// protocol credentials (Env, AuthToken, Headers, URL userinfo) masked.
func (r *RouteConfig) MaskSecrets() *RouteConfig {
	if r == nil {
		return nil
	}
	masked := r.Clone()
	for i := range masked.Protocols {
		masked.Protocols[i] = masked.Protocols[i].MaskSecrets()
	}
	return masked
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
	ProtocolID   string            `json:"protocol_id"`
	ProtocolName string            `json:"protocol_name"`
	TargetURL    string            `json:"target_url"`
	ToolName     string            `json:"tool_name"`
	RawToolName  string            `json:"raw_tool_name,omitempty"`
	Type         string            `json:"type"` // "stdio", "sse", "http"
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	Env          []string          `json:"env,omitempty"`
	AuthToken    string            `json:"auth_token,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	TargetScope  string            `json:"target_scope,omitempty"` // "local" or "corporate" / "upstream"
	AllowedTools []string          `json:"allowed_tools,omitempty"`
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

// MaxWireToolNameLen is the maximum character budget for FaradAiWire tool names in tools/list,
// leaving 20 characters of headroom for MCP client prefixes (e.g. "mcp__farad-ai-wire__" = 20,
// "mcp_farad-ai-wire_" = 18) within the 64-character LLM tool-name limit (`^[a-zA-Z0-9_-]{1,64}$`).
const MaxWireToolNameLen = 44

// SanitizeToolSegment normalizes a single tool or protocol segment to match `^[a-zA-Z0-9_-]+$`
// while collapsing consecutive underscores so a single segment never contains `"__"`.
func SanitizeToolSegment(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	lastWasUnderscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
			lastWasUnderscore = false
		} else if !lastWasUnderscore {
			b.WriteRune('_')
			lastWasUnderscore = true
		}
	}
	res := strings.Trim(b.String(), "_-")
	if res == "" {
		return "tool"
	}
	return res
}

func isLowerHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// extractTrailingHash4 extracts the 4-character hex discriminator from a protocol slug/ID
// (supporting both new `_[0-9a-f]{4}` and legacy `_[0-9a-f]{6}` where the first 4 hex chars
// equal `sha256[:2]`), returning `(stemWithoutHash, hash4, true)` when present.
func extractTrailingHash4(slug string) (string, string, bool) {
	lower := strings.ToLower(slug)
	idx := strings.LastIndexByte(lower, '_')
	if idx <= 0 {
		return "", "", false
	}
	suffix := lower[idx+1:]
	if len(suffix) == 4 && isLowerHex(suffix) {
		return lower[:idx], suffix, true
	}
	if len(suffix) == 6 && isLowerHex(suffix) {
		return lower[:idx], suffix[:4], true
	}
	return "", "", false
}

// CompactLegacyProtocolSlug normalizes a raw protocol ID/slug and compacts legacy
// `<profile>_<full_path>_<6hex>` identifiers (e.g. `antigravity_codegraph_696cf8` or
// `cline_github_com_..._sequentialthinking_516fbc`) to `<stem_max10>_<4hex>` (`codegraph_696c`,
// `sequential_516f`). Short or non-hash slugs (e.g. presets `context7`, `filesystem`) stay intact.
func CompactLegacyProtocolSlug(rawSlug string) string {
	s := strings.ToLower(strings.TrimSpace(rawSlug))
	if s == "" {
		return ""
	}
	s = strings.ToLower(SanitizeToolSegment(s))
	if len(s) <= 15 {
		return s
	}
	idx := strings.LastIndexByte(s, '_')
	if idx > 0 {
		suffix := s[idx+1:]
		if (len(suffix) == 6 || len(suffix) == 4) && isLowerHex(suffix) {
			hash4 := suffix[:4]
			prefix := s[:idx]
			// Take the last meaningful token of `<profile>_<path_tokens>`
			tokens := strings.Split(prefix, "_")
			leaf := prefix
			for i := len(tokens) - 1; i >= 0; i-- {
				tok := strings.TrimSpace(tokens[i])
				if tok == "" {
					continue
				}
				// Rejoin short trailing suffix like `_mcp` if preceding token exists (e.g. `context7_mcp` -> `context7_m`)
				if tok == "mcp" && i > 0 && tokens[i-1] != "" {
					leaf = tokens[i-1] + "_mcp"
				} else {
					leaf = tok
				}
				break
			}
			if len(leaf) > 10 {
				leaf = leaf[:10]
			}
			leaf = strings.Trim(leaf, "_-")
			if leaf == "" {
				leaf = "mcp"
			}
			return leaf + "_" + hash4
		}
	}
	if len(s) > 15 {
		sum := sha256.Sum256([]byte(s))
		stem := strings.Trim(s[:10], "_-")
		if stem == "" {
			stem = "mcp"
		}
		return stem + "_" + hex.EncodeToString(sum[:2])
	}
	return s
}

// FormatAggregatedToolName constructs a deterministic, `<= 44`-character aggregated tool name
// (`<mcpPrefix>__<toolName>`) shared by CompileToolsList and ResolveToolProtocol:
//  1. If `<protoSlug>__<cleanRaw>` fits in 44 chars, emit it directly.
//  2. If it exceeds 44 chars and `len(cleanRaw) <= 36`, keep `cleanRaw` 100% intact and narrow
//     `<protoSlug>` to `<shortStem>_<4hex>` (minimum 6 chars) so FindProtocol still resolves `_<4hex>`.
//  3. Only if `len(cleanRaw) > 36`, use a 6-char `<1char>_<4hex>` prefix and compact `cleanRaw` with `_[0-9a-f]{4}`.
func FormatAggregatedToolName(protoSlug, rawName string) string {
	slug := CompactLegacyProtocolSlug(protoSlug)
	trimmedRaw := rawName
	if slug != "" {
		trimmedRaw = strings.TrimPrefix(trimmedRaw, slug+"__")
	}
	if protoSlug != "" {
		trimmedRaw = strings.TrimPrefix(trimmedRaw, strings.ToLower(protoSlug)+"__")
		trimmedRaw = strings.TrimPrefix(trimmedRaw, protoSlug+"__")
	}
	cleanRaw := SanitizeToolSegment(trimmedRaw)
	if slug == "" {
		if len(cleanRaw) <= MaxWireToolNameLen {
			return cleanRaw
		}
		sum := sha256.Sum256([]byte(rawName))
		prefix := strings.Trim(cleanRaw[:MaxWireToolNameLen-5], "_-")
		if prefix == "" {
			prefix = "tool"
		}
		return prefix + "_" + hex.EncodeToString(sum[:2])
	}

	candidate := slug + "__" + cleanRaw
	if len(candidate) <= MaxWireToolNameLen {
		return candidate
	}

	stem, hash4, hasHash := extractTrailingHash4(slug)
	if !hasHash {
		sum := sha256.Sum256([]byte(slug))
		hash4 = hex.EncodeToString(sum[:2])
		stem = slug
	}
	if stem == "" {
		stem = "p"
	}

	// Tier 2: Preserve cleanRaw intact by narrowing the MCP prefix stem while retaining `_" + hash4`
	availSlug := MaxWireToolNameLen - 2 - len(cleanRaw) // space before "__" + cleanRaw
	availStem := availSlug - 5                          // space before "_" + hash4 (5 chars)
	if availStem >= 1 {
		shortStem := stem
		if len(shortStem) > availStem {
			shortStem = shortStem[:availStem]
		}
		shortStem = strings.Trim(shortStem, "_-")
		if shortStem == "" {
			shortStem = stem[:1]
		}
		return shortStem + "_" + hash4 + "__" + cleanRaw
	}

	// Tier 3: Extreme raw tool name (> 36 chars) — minimum 6-char `<1char>_<4hex>` slug + compacted rawName
	minSlug := strings.Trim(stem[:1], "_-")
	if minSlug == "" {
		minSlug = "p"
	}
	minSlug = minSlug + "_" + hash4 // 6 chars
	maxRawPart := MaxWireToolNameLen - len(minSlug) - 2
	rawSum := sha256.Sum256([]byte(rawName))
	rawHash4 := hex.EncodeToString(rawSum[:2])
	rawPrefixLen := maxRawPart - 5
	if rawPrefixLen < 1 {
		rawPrefixLen = 1
	}
	rawPrefix := cleanRaw
	if len(rawPrefix) > rawPrefixLen {
		rawPrefix = rawPrefix[:rawPrefixLen]
	}
	rawPrefix = strings.Trim(rawPrefix, "_-")
	if rawPrefix == "" {
		rawPrefix = "t"
	}
	return minSlug + "__" + rawPrefix + "_" + rawHash4
}

// GetProtocolSlug returns the clean slug/prefix for an MCP protocol.
func GetProtocolSlug(proto *ProtocolConfig) string {
	if proto == nil {
		return ""
	}
	if proto.Name != "" && !strings.Contains(proto.Name, " ") && strings.HasSuffix(proto.ID, "-proto") {
		return CompactLegacyProtocolSlug(proto.Name)
	}
	if proto.ID != "" && !strings.Contains(proto.ID, " ") {
		return CompactLegacyProtocolSlug(proto.ID)
	}
	if proto.Name != "" {
		if !strings.Contains(proto.Name, " ") {
			return CompactLegacyProtocolSlug(proto.Name)
		}
		if proto.ID != "" {
			return CompactLegacyProtocolSlug(strings.ReplaceAll(proto.ID, " ", "_"))
		}
		return CompactLegacyProtocolSlug(strings.ReplaceAll(proto.Name, " ", "_"))
	}
	return ""
}

// FindProtocol attempts to locate an attached protocol by ID, Name, protocol slug, or narrowed `<stem>_<4hex>` prefix.
func (r *RouteConfig) FindProtocol(nameOrID string) *ProtocolConfig {
	if r == nil || nameOrID == "" {
		return nil
	}
	for i := range r.Protocols {
		slug := GetProtocolSlug(&r.Protocols[i])
		if strings.EqualFold(r.Protocols[i].Name, nameOrID) ||
			strings.EqualFold(r.Protocols[i].ID, nameOrID) ||
			(slug != "" && strings.EqualFold(slug, nameOrID)) ||
			(r.Protocols[i].ID != "" && strings.EqualFold(CompactLegacyProtocolSlug(r.Protocols[i].ID), CompactLegacyProtocolSlug(nameOrID))) {
			return &r.Protocols[i]
		}
	}

	// Fallback for narrowed prefixes produced by FormatAggregatedToolName (e.g. `seq_516f` matching `sequential_516f`)
	if reqStem, reqHash4, ok := extractTrailingHash4(nameOrID); ok {
		var hashMatch *ProtocolConfig
		hashMatchCount := 0
		for i := range r.Protocols {
			p := &r.Protocols[i]
			pSlug := GetProtocolSlug(p)
			pStem, pHash4, pOk := extractTrailingHash4(pSlug)
			if !pOk {
				pStem, pHash4, pOk = extractTrailingHash4(p.ID)
			}
			if !pOk || pHash4 != reqHash4 {
				continue
			}
			hashMatch = p
			hashMatchCount++
			if strings.HasPrefix(pStem, reqStem) {
				return p
			}
		}
		if hashMatchCount == 1 {
			return hashMatch
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
	var incomingProto *ProtocolConfig
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		incomingProto = r.FindProtocol(parts[0])
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
		if incomingProto != nil && strings.Contains(allowed, "__") {
			ap := strings.SplitN(allowed, "__", 2)
			if strings.EqualFold(ap[1], cleanName) && r.FindProtocol(ap[0]) == incomingProto {
				return true
			}
		}
	}
	return false
}

// GetToolGovernanceMode returns the configured ToolGovernanceMode for a tool, or fallback if unconfigured.
// Fast-path exact lookup avoids heap allocations; case-insensitive EqualFold fallback prevents bypass via casing variations.
func (r *RouteConfig) GetToolGovernanceMode(toolName string) (ToolGovernanceMode, bool) {
	if r == nil || len(r.ToolGovernance) == 0 {
		return "", false
	}
	if mode, ok := r.ToolGovernance[toolName]; ok && mode.IsValid() {
		return mode, true
	}
	var rawTool string
	var incomingProto *ProtocolConfig
	hasPrefix := false
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		incomingProto = r.FindProtocol(parts[0])
		rawTool = parts[1]
		hasPrefix = true
		if mode, ok := r.ToolGovernance[rawTool]; ok && mode.IsValid() {
			return mode, true
		}
	}
	for configuredName, mode := range r.ToolGovernance {
		if !mode.IsValid() {
			continue
		}
		if strings.EqualFold(configuredName, toolName) || (hasPrefix && strings.EqualFold(configuredName, rawTool)) {
			return mode, true
		}
		if incomingProto != nil && strings.Contains(configuredName, "__") {
			cp := strings.SplitN(configuredName, "__", 2)
			if strings.EqualFold(cp[1], rawTool) && r.FindProtocol(cp[0]) == incomingProto {
				return mode, true
			}
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
