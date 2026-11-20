package admin

import "github.com/FaradAiLab/FaradAiWire/internal/agent"

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
	SchemaValidation         *agent.SchemaValidationOverride                `json:"schema_validation,omitempty"`
	Guard                    *agent.GuardOverride                           `json:"guard,omitempty"`
}

// ToUpdateSpec converts the HTTP payload into a domain agent.UpdateSpec.
func (p AgentPayload) ToUpdateSpec(protocols []agent.ProtocolConfig, protocolsUpdated bool) agent.UpdateSpec {
	return agent.UpdateSpec{
		Description:              p.Description,
		RoutingMode:              p.RoutingMode,
		Protocols:                protocols,
		ProtocolsUpdated:         protocolsUpdated,
		EnabledTools:             p.EnabledTools,
		ToolOverrides:            p.ToolOverrides,
		ToolGovernance:           p.ToolGovernance,
		RetainedGovernance:       p.RetainedGovernance,
		RestoreRetainedProtocols: p.RestoreRetainedProtocols,
		RateLimit:                p.RateLimit,
		LoopProtection:           p.LoopProtection,
		SchemaValidation:         p.SchemaValidation,
		Guard:                    p.Guard,
	}
}
