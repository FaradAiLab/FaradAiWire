package agent

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_ErrorsIsMatching(t *testing.T) {
	// 1. Agent Not Found wrapping
	errAgent := NewAgentNotFoundError("support-bot")
	if !errors.Is(errAgent, ErrAgentNotFound) {
		t.Errorf("expected errors.Is(errAgent, ErrAgentNotFound) to be true, got false")
	}

	// 2. Protocol Not Found wrapping
	errProto := NewProtocolNotFoundError("support-bot", "sql-tool")
	if !errors.Is(errProto, ErrProtocolNotFound) {
		t.Errorf("expected errors.Is(errProto, ErrProtocolNotFound) to be true, got false")
	}

	// 3. Routing Mode Violation wrapping
	errRoute := NewRoutingModeViolationError("support-bot", "DIRECT", "use /sse/support-bot/{protocol}")
	if !errors.Is(errRoute, ErrRoutingModeViolation) {
		t.Errorf("expected errors.Is(errRoute, ErrRoutingModeViolation) to be true, got false")
	}

	// 4. Upstream Unavailable
	errUpstream := fmt.Errorf("%w: connection refused to 127.0.0.1:9090", ErrUpstreamUnavailable)
	if !errors.Is(errUpstream, ErrUpstreamUnavailable) {
		t.Errorf("expected errors.Is(errUpstream, ErrUpstreamUnavailable) to be true, got false")
	}

	// 5. Cross-error mismatch
	if errors.Is(errAgent, ErrProtocolNotFound) {
		t.Errorf("expected ErrAgentNotFound to not match ErrProtocolNotFound")
	}
}
