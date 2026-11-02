package dlp

import (
	"context"
	"regexp"
)

// Action represents the policy enforcement action when a DLP pattern matches.
type Action string

const (
	ActionMask  Action = "mask"
	ActionBlock Action = "block"
	ActionHITL  Action = "hitl"
	ActionAudit Action = "audit"
)

// CompiledPattern encapsulates an immutable regular expression rule with its associated action.
type CompiledPattern struct {
	Regex       *regexp.Regexp
	Name        string
	Action      Action
	Placeholder string
	CWE         string
	Severity    string
}

// DirectionFlags defines bitmask flags for directional tool exemptions.
type DirectionFlags uint8

const (
	FlagExemptRequest  DirectionFlags = 1 << 0
	FlagExemptResponse DirectionFlags = 1 << 1
)

// RuleSet holds the resolved DLP rules and tool exemptions for an execution context.
type RuleSet struct {
	Enabled        bool
	Patterns       []CompiledPattern
	ToolExemptions map[string]DirectionFlags
}

// IsExempt reports whether the specified tool is exempt in the given direction.
func (r RuleSet) IsExempt(toolName string, flag DirectionFlags) bool {
	if toolName == "" || len(r.ToolExemptions) == 0 {
		return false
	}
	flags, exists := r.ToolExemptions[toolName]
	return exists && (flags&flag != 0)
}

// RuleProvider abstracts the retrieval and caching of DLP rules (Dependency Inversion Principle).
type RuleProvider interface {
	ResolveRules(ctx context.Context) RuleSet
}

// Reloader defines an optional interface for providers supporting manual cache eviction.
type Reloader interface {
	Reload(agentName string)
}

// ReloaderFunc allows using ordinary functions as DLP Reloader implementations.
type ReloaderFunc func(agentName string)

// Reload calls f(agentName).
func (f ReloaderFunc) Reload(agentName string) {
	f(agentName)
}
