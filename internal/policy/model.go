package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
)

// Domain error definitions for policy catalog and DLP governance.
var (
	// ErrRuleNotFound is returned when a DLP pattern rule does not exist.
	ErrRuleNotFound = errors.New("policy rule not found")
	// ErrPackNotFound is returned when a policy pack does not exist.
	ErrPackNotFound = errors.New("policy pack not found")
	// ErrConfigNotFound is returned when an agent policy configuration does not exist.
	ErrConfigNotFound = errors.New("agent policy configuration not found")
	// ErrRuleAlreadyExists is returned when attempting to create a duplicate rule.
	ErrRuleAlreadyExists = errors.New("policy rule already exists")
	// ErrPackAlreadyExists is returned when attempting to create a duplicate pack.
	ErrPackAlreadyExists = errors.New("policy pack already exists")
	// ErrInvalidRegex is returned when a regex fails compilation.
	ErrInvalidRegex = errors.New("invalid regular expression syntax")
	// ErrInvalidAction is returned when an unknown action is supplied.
	ErrInvalidAction = errors.New("invalid dlp action: must be 'mask', 'block', 'hitl', or 'audit'")
	// ErrImmutableBuiltin is returned when attempting to delete or overwrite a builtin item.
	ErrImmutableBuiltin = errors.New("cannot delete or modify immutable builtin policy rule or pack")
	// ErrInvalidIdentifier is returned when an identifier contains illegal characters.
	ErrInvalidIdentifier = errors.New("identifier contains illegal characters or path traversal attempt")
)

// Action aliases the filter/dlp.Action for consistent domain semantics.
type Action = dlp.Action

const (
	ActionMask  Action = dlp.ActionMask
	ActionBlock Action = dlp.ActionBlock
	ActionHITL  Action = dlp.ActionHITL
	ActionAudit Action = dlp.ActionAudit
)

// ActionPrecedenceWeight returns the restriction hierarchy weight:
// BLOCK (4) > HITL (3) > MASK (2) > AUDIT (1).
func ActionPrecedenceWeight(a Action) int {
	switch a {
	case ActionBlock:
		return 4
	case ActionHITL:
		return 3
	case ActionMask:
		return 2
	case ActionAudit:
		return 1
	default:
		return 0
	}
}

// MostRestrictiveAction compares two actions and returns the one with higher restriction.
func MostRestrictiveAction(a, b Action) Action {
	if ActionPrecedenceWeight(a) >= ActionPrecedenceWeight(b) {
		return a
	}
	return b
}

// IsValidAction checks if the action string is one of the supported DLP actions.
func IsValidAction(a Action) bool {
	switch a {
	case ActionMask, ActionBlock, ActionHITL, ActionAudit:
		return true
	default:
		return false
	}
}

// DlpPatternRule defines an individual regex-based data loss prevention pattern.
// Struct fields are ordered by alignment to minimize padding overhead.
type DlpPatternRule struct {
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Category      string    `json:"category"`
	Regex         string    `json:"regex"`
	DefaultAction Action    `json:"default_action"`
	CWE           string    `json:"cwe,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	IsBuiltin     bool      `json:"is_builtin"`
}

// PolicyPack groups a collection of rules for regional compliance or technical domains.
type PolicyPack struct {
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Category    string           `json:"category"`
	RuleIDs     []string         `json:"rule_ids"`
	Rules       []DlpPatternRule `json:"rules,omitempty"`
	IsBuiltin   bool             `json:"is_builtin"`
}

// RuleOverride allows an agent to bypass or alter the enforcement action of an inherited rule.
type RuleOverride struct {
	RuleID  string `json:"rule_id"`
	Action  Action `json:"action"`
	Enabled bool   `json:"enabled"`
}

// CustomPattern allows specifying agent-scoped regex rules without modifying global packs.
type CustomPattern struct {
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Action Action `json:"action"`
}

// ToolExemption defines directional bypass controls for an MCP tool.
type ToolExemption struct {
	Request  bool `json:"request"`  // Bypass DLP on incoming tool call arguments
	Response bool `json:"response"` // Bypass DLP on outgoing tool execution result
}

// AgentPolicyConfig stores the policy pack attachments and overrides for a specific agent.
type AgentPolicyConfig struct {
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
	AgentName      string                   `json:"agent_name"`
	PackIDs        []string                 `json:"pack_ids"`
	Overrides      []RuleOverride           `json:"overrides"`
	CustomPatterns []CustomPattern          `json:"custom_patterns"`
	ToolExemptions map[string]ToolExemption `json:"tool_exemptions"`
}

// Recommendation represents a smart policy pack recommendation based on attached MCPs.
type Recommendation struct {
	PackID       string   `json:"pack_id"`
	PackName     string   `json:"pack_name"`
	Rationale    string   `json:"rationale"`
	MatchedTools []string `json:"matched_tools,omitempty"`
}

var safeIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.:]+$`)

// ValidateIdentifier ensures an identifier (rule ID, pack ID, agent name) contains only
// safe alphanumeric, hyphen, underscore, dot, or colon characters and no traversal components.
func ValidateIdentifier(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%w: identifier cannot be empty", ErrInvalidIdentifier)
	}
	if strings.Contains(trimmed, "\x00") ||
		strings.Contains(trimmed, "/") ||
		strings.Contains(trimmed, "\\") ||
		strings.Contains(trimmed, "..") {
		return fmt.Errorf("%w: illegal traversal sequence in '%s'", ErrInvalidIdentifier, id)
	}
	if !safeIDRegex.MatchString(trimmed) {
		return fmt.Errorf("%w: '%s' contains invalid characters", ErrInvalidIdentifier, id)
	}
	return nil
}

// ValidateRule validates the fields of a DlpPatternRule, verifying identifier and regex syntax.
func ValidateRule(rule *DlpPatternRule) error {
	if rule == nil {
		return errors.New("rule cannot be nil")
	}
	if err := ValidateIdentifier(rule.ID); err != nil {
		return err
	}
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("rule name cannot be empty")
	}
	if !IsValidAction(rule.DefaultAction) {
		return ErrInvalidAction
	}
	if strings.TrimSpace(rule.Regex) == "" {
		return errors.New("rule regex cannot be empty")
	}
	if _, err := regexp.Compile(rule.Regex); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegex, err)
	}
	return nil
}

// ValidatePack validates the fields of a PolicyPack.
func ValidatePack(pack *PolicyPack) error {
	if pack == nil {
		return errors.New("pack cannot be nil")
	}
	if err := ValidateIdentifier(pack.ID); err != nil {
		return err
	}
	if strings.TrimSpace(pack.Name) == "" {
		return errors.New("pack name cannot be empty")
	}
	for _, ruleID := range pack.RuleIDs {
		if err := ValidateIdentifier(ruleID); err != nil {
			return fmt.Errorf("invalid rule id '%s' in pack: %w", ruleID, err)
		}
	}
	return nil
}

// ValidateAgentPolicyConfig validates an AgentPolicyConfig.
func ValidateAgentPolicyConfig(cfg *AgentPolicyConfig) error {
	if cfg == nil {
		return errors.New("agent policy configuration cannot be nil")
	}
	if err := ValidateIdentifier(cfg.AgentName); err != nil {
		return fmt.Errorf("agent name validation failed: %w", err)
	}
	for _, packID := range cfg.PackIDs {
		if err := ValidateIdentifier(packID); err != nil {
			return fmt.Errorf("invalid pack id '%s': %w", packID, err)
		}
	}
	for _, o := range cfg.Overrides {
		if err := ValidateIdentifier(o.RuleID); err != nil {
			return fmt.Errorf("invalid rule override id '%s': %w", o.RuleID, err)
		}
		if o.Action != "" && !IsValidAction(o.Action) {
			return fmt.Errorf("invalid override action '%s': %w", o.Action, ErrInvalidAction)
		}
	}
	for _, cp := range cfg.CustomPatterns {
		if strings.TrimSpace(cp.Name) == "" {
			return errors.New("custom pattern name cannot be empty")
		}
		if !IsValidAction(cp.Action) {
			return fmt.Errorf("invalid custom pattern action '%s': %w", cp.Action, ErrInvalidAction)
		}
		if _, err := regexp.Compile(cp.Regex); err != nil {
			return fmt.Errorf("invalid custom pattern regex: %w", err)
		}
	}
	for toolName := range cfg.ToolExemptions {
		if strings.TrimSpace(toolName) == "" {
			return errors.New("tool exemption name cannot be empty")
		}
	}
	return nil
}

// Store defines the persistence contract for managing DLP rules, policy packs,
// and agent policy configurations in persistent storage.
type Store interface {
	// Migrate creates or updates the database schema for policy governance.
	Migrate(ctx context.Context) error

	// Rules
	ListRules(ctx context.Context, category string) ([]DlpPatternRule, error)
	GetRule(ctx context.Context, id string) (*DlpPatternRule, error)
	CreateRule(ctx context.Context, rule *DlpPatternRule) error
	UpdateRule(ctx context.Context, rule *DlpPatternRule) error
	DeleteRule(ctx context.Context, id string) error

	// Packs
	ListPacks(ctx context.Context) ([]PolicyPack, error)
	GetPack(ctx context.Context, id string) (*PolicyPack, error)
	CreatePack(ctx context.Context, pack *PolicyPack) error
	UpdatePack(ctx context.Context, pack *PolicyPack) error
	DeletePack(ctx context.Context, id string) error

	// Agent Policy Configurations
	GetAgentConfig(ctx context.Context, agentName string) (*AgentPolicyConfig, error)
	SaveAgentConfig(ctx context.Context, config *AgentPolicyConfig) error
	ListAgentsUsingPack(ctx context.Context, packID string) ([]string, error)

	// Close terminates any underlying resources.
	Close() error
}
