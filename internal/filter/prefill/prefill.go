package prefill

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Ensure PrefillFilter implements filter.SecurityFilter and filter.RequestFilter.
var (
	_ filter.SecurityFilter = (*PrefillFilter)(nil)
	_ filter.RequestFilter  = (*PrefillFilter)(nil)
)

// PrefillFilter prevents "sockpuppeting" attacks by blocking requests where the message history ends with an assistant role.
type PrefillFilter struct {
	enabled bool
}

// NewPrefillFilter initializes a PrefillFilter.
func NewPrefillFilter(enabled bool) *PrefillFilter {
	return &PrefillFilter{enabled: enabled}
}

// Name returns the identifier of the filter.
func (p *PrefillFilter) Name() string {
	return "prefill_block"
}

// Order returns the pipeline execution precedence (OrderPrefill = 5).
func (p *PrefillFilter) Order() int {
	return filter.OrderPrefill
}

// Message represents a generic chat message structure.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// FilterRequest checks if the incoming request contains chat messages and blocks assistant prefill.
func (p *PrefillFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if !p.enabled {
		return req, nil
	}

	// 1. Check if the parameters contain a "messages" array (standard Chat Completions format)
	if len(req.Params) == 0 {
		return req, nil
	}

	// In-memory byte pattern fast-path bailout: if "messages" is absent, non-chat tool calls bypass JSON parsing completely.
	if !bytes.Contains(req.Params, []byte(`"messages"`)) {
		return req, nil
	}

	// Try parsing messages from direct params
	var directParams struct {
		Messages []Message `json:"messages"`
	}
	if err := json.Unmarshal(req.Params, &directParams); err == nil && len(directParams.Messages) > 0 {
		if isLastMessageAssistant(directParams.Messages) {
			return nil, mcp.NewError(mcp.ErrPrefillInjection, "Assistant prefill injection blocked (sockpuppeting defense)", nil)
		}
	}

	// Try parsing if params contain nested structures (e.g. tools/call arguments containing messages)
	var toolCallParams struct {
		Arguments struct {
			Messages []Message `json:"messages"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &toolCallParams); err == nil && len(toolCallParams.Arguments.Messages) > 0 {
		if isLastMessageAssistant(toolCallParams.Arguments.Messages) {
			return nil, mcp.NewError(mcp.ErrPrefillInjection, "Assistant prefill injection in tool arguments blocked", nil)
		}
	}

	return req, nil
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (p *PrefillFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := p.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (p *PrefillFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return resp, nil
}

func isLastMessageAssistant(messages []Message) bool {
	if len(messages) == 0 {
		return false
	}
	lastMsg := messages[len(messages)-1]
	return lastMsg.Role == "assistant"
}
