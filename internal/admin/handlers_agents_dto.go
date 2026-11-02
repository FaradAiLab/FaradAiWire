package admin

import (
	"fmt"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

// AgentPayload encapsulates incoming HTTP JSON payload for creating or modifying agents.
type AgentPayload struct {
	AgentName                string                                         `json:"agent_name"`
	Name                     string                                         `json:"name,omitempty"`
	AgentID                  string                                         `json:"agent_id,omitempty"`
	Description              string                                         `json:"description,omitempty"`
	RoutingMode              string                                         `json:"routing_mode,omitempty"`
	Protocols                []agent.ProtocolConfig                         `json:"protocols,omitempty"`
	ProtocolIDs              []string                                       `json:"protocol_ids,omitempty"`
	ClearAllProtocols        bool                                           `json:"clear_all_protocols,omitempty"`
	EnabledTools             []string                                       `json:"enabled_tools,omitempty"`
	ToolOverrides            *agent.ToolOverrides                           `json:"tool_overrides,omitempty"`
	ToolGovernance           map[string]agent.ToolGovernanceMode            `json:"tool_governance,omitempty"`
	RetainedGovernance       map[string]map[string]agent.ToolGovernanceMode `json:"retained_governance,omitempty"`
	RestoreRetainedProtocols []string                                       `json:"restore_retained_protocols,omitempty"`
	RateLimit                *agent.RateLimitOverride                       `json:"rate_limit,omitempty"`
	LoopProtection           *agent.LoopProtectionOverride                  `json:"loop_protection,omitempty"`
}

func validateRateLimit(r *agent.RateLimitOverride) error {
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

func validateLoopProtection(l *agent.LoopProtectionOverride) error {
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

func validateToolGovernance(gov map[string]agent.ToolGovernanceMode) error {
	for tool, mode := range gov {
		if !mode.IsValid() {
			return fmt.Errorf("invalid tool governance mode '%s' for tool '%s'", mode, tool)
		}
	}
	return nil
}

func validateRetainedGovernance(retained map[string]map[string]agent.ToolGovernanceMode) error {
	for proto, tools := range retained {
		for tool, mode := range tools {
			if !mode.IsValid() {
				return fmt.Errorf("invalid retained tool governance mode '%s' for protocol '%s', tool '%s'", mode, proto, tool)
			}
		}
	}
	return nil
}

