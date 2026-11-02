package agent

import (
	"errors"
	"fmt"
)

var (
	// ErrAgentNotFound is returned when an agent directory or configuration cannot be found.
	ErrAgentNotFound = errors.New("AGENT_NOT_FOUND: agent config not found")

	// ErrProtocolNotFound is returned when a requested protocol is not attached to the agent.
	ErrProtocolNotFound = errors.New("MCP_NOT_FOUND: protocol is not attached to agent")

	// ErrRoutingModeViolation is returned when an ingress path violates the configured agent routing mode.
	ErrRoutingModeViolation = errors.New("ROUTING_VIOLATION: invalid routing path for agent mode")

	// ErrManifestNotFound is returned when an agent tools_manifest.json is missing or unreadable.
	ErrManifestNotFound = errors.New("MANIFEST_NOT_FOUND: agent tools manifest not found")

	// ErrInvalidIdentifier is returned when an agent identifier fails pathguard validation.
	ErrInvalidIdentifier = errors.New("INVALID_IDENTIFIER: agent identifier contains unsafe characters")

	// ErrUpstreamUnavailable is returned when upstream SSE or MCP backend is unreachable or degraded.
	ErrUpstreamUnavailable = errors.New("UPSTREAM_UNAVAILABLE: upstream MCP server is unreachable")
)

// NewRoutingModeViolationError constructs a detailed routing mode violation error.
func NewRoutingModeViolationError(agentName, expectedMode, suggestion string) error {
	return fmt.Errorf("%w: Agent '%s' is configured in %s mode. %s", ErrRoutingModeViolation, agentName, expectedMode, suggestion)
}

// NewProtocolNotFoundError constructs a detailed protocol not found error.
func NewProtocolNotFoundError(agentName, protocolName string) error {
	return fmt.Errorf("%w: Protocol '%s' is not attached to agent '%s'", ErrProtocolNotFound, protocolName, agentName)
}

// NewAgentNotFoundError constructs a detailed agent not found error.
func NewAgentNotFoundError(agentName string) error {
	return fmt.Errorf("%w: Agent '%s' config not found", ErrAgentNotFound, agentName)
}
