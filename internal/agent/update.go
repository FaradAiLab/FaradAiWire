package agent

import (
	"fmt"
	"slices"
	"strings"
)

// UpdateValidationError represents a typed validation failure on an agent configuration update.
type UpdateValidationError struct {
	Code string
	Err  error
}

// Error implements the error interface.
func (e *UpdateValidationError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the underlying validation error.
func (e *UpdateValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// UpdateSpec describes a partial or full administrative update to an existing RouteConfig.
type UpdateSpec struct {
	Description              string
	RoutingMode              string
	Protocols                []ProtocolConfig
	ProtocolsUpdated         bool
	EnabledTools             []string
	ToolOverrides            *ToolOverrides
	ToolGovernance           map[string]ToolGovernanceMode
	RetainedGovernance       map[string]map[string]ToolGovernanceMode
	RestoreRetainedProtocols []string
	RateLimit                *RateLimitOverride
	LoopProtection           *LoopProtectionOverride
	SchemaValidation         *SchemaValidationOverride
	Guard                    *GuardOverride
}

// Validate verifies governance modes and numerical bounds on an UpdateSpec.
func (s UpdateSpec) Validate() *UpdateValidationError {
	checks := []struct {
		code string
		err  error
	}{
		{"INVALID_GOVERNANCE_MODE", validateToolGovernanceMap(s.ToolGovernance)},
		{"INVALID_RETAINED_GOVERNANCE_MODE", validateRetainedGovernanceMap(s.RetainedGovernance)},
		{"INVALID_RATE_LIMIT", validateRateLimitOverride(s.RateLimit)},
		{"INVALID_LOOP_PROTECTION", validateLoopProtectionOverride(s.LoopProtection)},
		{"INVALID_SCHEMA_VALIDATION", validateSchemaValidationOverride(s.SchemaValidation)},
		{"INVALID_GUARD_OVERRIDE", validateGuardOverrideConfig(s.Guard)},
	}
	for _, c := range checks {
		if c.err != nil {
			return &UpdateValidationError{Code: c.code, Err: c.err}
		}
	}
	return nil
}

func validateSchemaValidationOverride(s *SchemaValidationOverride) error {
	if s == nil {
		return nil
	}
	if !s.Mode.IsValid() {
		return fmt.Errorf("invalid schema_validation mode '%s': allowed values are 'enforce', 'audit', or 'off'", s.Mode)
	}
	return nil
}

func validateGuardOverrideConfig(g *GuardOverride) error {
	if g == nil {
		return nil
	}
	if !g.Mode.IsValid() {
		return fmt.Errorf("invalid guard mode '%s': allowed values are 'enforce', 'audit', or 'off'", g.Mode)
	}
	return nil
}

func validateRateLimitOverride(r *RateLimitOverride) error {
	if r == nil {
		return nil
	}
	if r.MaxBurst < 0 {
		return fmt.Errorf("rate_limit max_burst cannot be negative")
	}
	if r.RefillRate < 0 {
		return fmt.Errorf("rate_limit refill_rate cannot be negative")
	}
	return nil
}

func validateLoopProtectionOverride(l *LoopProtectionOverride) error {
	if l == nil {
		return nil
	}
	if l.MaxRepeat < 0 {
		return fmt.Errorf("loop_protection max_repeat cannot be negative")
	}
	if l.WindowSeconds < 0 {
		return fmt.Errorf("loop_protection window_seconds cannot be negative")
	}
	return nil
}

func validateToolGovernanceMap(gov map[string]ToolGovernanceMode) error {
	for tool, mode := range gov {
		if !mode.IsValid() {
			return fmt.Errorf("invalid tool governance mode '%s' for tool '%s'", mode, tool)
		}
	}
	return nil
}

func validateRetainedGovernanceMap(retained map[string]map[string]ToolGovernanceMode) error {
	for proto, tools := range retained {
		for tool, mode := range tools {
			if !mode.IsValid() {
				return fmt.Errorf("invalid retained tool governance mode '%s' for protocol '%s', tool '%s'", mode, proto, tool)
			}
		}
	}
	return nil
}

// ToolBelongsToProtocol determines if toolName is owned by a given protocol via prefix or manifest lookup.
func ToolBelongsToProtocol(toolName, protoID, protoName string, manifest []ToolMetadata) bool {
	protoIDLower := strings.ToLower(strings.TrimSpace(protoID))
	protoSlugLower := CompactLegacyProtocolSlug(protoIDLower)
	protoNameLower := strings.ToLower(strings.TrimSpace(protoName))
	toolLower := strings.ToLower(toolName)

	if protoIDLower != "" && strings.HasPrefix(toolLower, protoIDLower+"__") {
		return true
	}
	if protoSlugLower != "" && strings.HasPrefix(toolLower, protoSlugLower+"__") {
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

// ApplyUpdate applies spec onto c in place, managing protocol attachment transitions and
// stashing/restoring per-protocol RetainedGovernance rules cleanly.
func (c *RouteConfig) ApplyUpdate(spec UpdateSpec, manifest []ToolMetadata) {
	if c == nil {
		return
	}

	if spec.Description != "" {
		c.Description = spec.Description
	}
	if spec.RoutingMode != "" {
		c.RoutingMode = strings.ToLower(strings.TrimSpace(spec.RoutingMode))
	}

	// Capture prior protocols and stash detached protocol governance rules before overwriting ToolGovernance.
	if spec.ProtocolsUpdated {
		oldProtocols := c.Protocols
		if spec.Protocols == nil {
			c.Protocols = []ProtocolConfig{}
		} else {
			c.Protocols = make([]ProtocolConfig, len(spec.Protocols))
			for i := range spec.Protocols {
				c.Protocols[i] = spec.Protocols[i].Clone()
			}
		}
		c.stashDetachedProtocolGovernance(oldProtocols, manifest)
	}

	if spec.EnabledTools != nil {
		c.EnabledTools = slices.Clone(spec.EnabledTools)
	}
	if spec.ToolOverrides != nil {
		c.ToolOverrides = &ToolOverrides{
			EnabledTools: slices.Clone(spec.ToolOverrides.EnabledTools),
		}
	}
	if spec.ToolGovernance != nil {
		c.ToolGovernance = make(map[string]ToolGovernanceMode, len(spec.ToolGovernance))
		for k, v := range spec.ToolGovernance {
			c.ToolGovernance[k] = v
		}
	}
	if spec.RetainedGovernance != nil {
		if c.RetainedGovernance == nil {
			c.RetainedGovernance = make(map[string]map[string]ToolGovernanceMode, len(spec.RetainedGovernance))
		}
		for k, v := range spec.RetainedGovernance {
			toolsMap := make(map[string]ToolGovernanceMode, len(v))
			for tk, tv := range v {
				toolsMap[tk] = tv
			}
			c.RetainedGovernance[k] = toolsMap
		}
	}

	// Restore retained protocols AFTER applying spec.ToolGovernance so restored rules merge cleanly
	// without overwriting explicit overrides from the payload.
	if spec.ProtocolsUpdated && len(spec.RestoreRetainedProtocols) > 0 {
		c.restoreRetainedProtocolGovernance(spec.RestoreRetainedProtocols)
	}

	if spec.RateLimit != nil {
		cp := *spec.RateLimit
		c.RateLimit = &cp
	}
	if spec.LoopProtection != nil {
		cp := *spec.LoopProtection
		cp.ExcludeTools = slices.Clone(spec.LoopProtection.ExcludeTools)
		c.LoopProtection = &cp
	}
	if spec.SchemaValidation != nil {
		cp := *spec.SchemaValidation
		c.SchemaValidation = &cp
	}
	if spec.Guard != nil {
		cp := *spec.Guard
		c.Guard = &cp
	}
}

func (c *RouteConfig) stashDetachedProtocolGovernance(oldProtocols []ProtocolConfig, manifest []ToolMetadata) {
	newProtoSet := make(map[string]bool, len(c.Protocols))
	for _, p := range c.Protocols {
		pid := p.ID
		if pid == "" {
			pid = p.Name
		}
		newProtoSet[strings.ToLower(pid)] = true
	}

	for _, oldP := range oldProtocols {
		oldPID := oldP.ID
		if oldPID == "" {
			oldPID = oldP.Name
		}
		if newProtoSet[strings.ToLower(oldPID)] {
			continue
		}
		for toolName, mode := range c.ToolGovernance {
			if ToolBelongsToProtocol(toolName, oldPID, oldP.Name, manifest) {
				if c.RetainedGovernance == nil {
					c.RetainedGovernance = make(map[string]map[string]ToolGovernanceMode)
				}
				if c.RetainedGovernance[oldPID] == nil {
					c.RetainedGovernance[oldPID] = make(map[string]ToolGovernanceMode)
				}
				c.RetainedGovernance[oldPID][toolName] = mode
				delete(c.ToolGovernance, toolName)
			}
		}
	}
}

func (c *RouteConfig) restoreRetainedProtocolGovernance(restorePIDs []string) {
	for _, restorePID := range restorePIDs {
		pidClean := strings.TrimSpace(restorePID)
		for retainedKey, savedRules := range c.RetainedGovernance {
			if !strings.EqualFold(retainedKey, pidClean) {
				continue
			}
			if c.ToolGovernance == nil {
				c.ToolGovernance = make(map[string]ToolGovernanceMode, len(savedRules))
			}
			for toolName, mode := range savedRules {
				if _, explicitlySet := c.ToolGovernance[toolName]; !explicitlySet {
					c.ToolGovernance[toolName] = mode
				}
			}
			delete(c.RetainedGovernance, retainedKey)
		}
	}
}
