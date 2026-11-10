package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/console"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Ensure HITLFilter implements filter.SecurityFilter and filter.RequestFilter.
var (
	_ filter.SecurityFilter = (*HITLFilter)(nil)
	_ filter.RequestFilter  = (*HITLFilter)(nil)
)

// HITLApprover abstracts dual-channel human-in-the-loop approval escalation.
type HITLApprover = hitltypes.HITLApprover

// HITLFilter intercepts destructive tool calls and prompts for human confirmation.
type HITLFilter struct {
	enabled          bool
	destructiveTools map[string]bool
	approvalMode     string // "cli" or "webhook"
	webhookURL       string
	timeout          time.Duration
	httpClient       *http.Client
	ssrfOpts         transport.SafeTransportOptions
	cliIn            io.Reader
	cliOut           io.Writer
	hitlDispatcher   HITLApprover
	mu               sync.RWMutex
}

// NewHITLFilter initializes a HITLFilter using default SSRF safe egress guardrails.
func NewHITLFilter(enabled bool, destructiveTools []string, approvalMode, webhookURL string, timeoutSeconds int) *HITLFilter {
	return NewHITLFilterWithSSRF(enabled, destructiveTools, approvalMode, webhookURL, timeoutSeconds, transport.DefaultSafeOptions())
}

// NewHITLFilterWithSSRF initializes a HITLFilter with explicit SSRF safe options.
func NewHITLFilterWithSSRF(enabled bool, destructiveTools []string, approvalMode, webhookURL string, timeoutSeconds int, ssrfOpts transport.SafeTransportOptions) *HITLFilter {
	toolsMap := make(map[string]bool, len(destructiveTools))
	for _, t := range destructiveTools {
		if norm := strings.ToLower(strings.TrimSpace(t)); norm != "" {
			toolsMap[norm] = true
		}
	}

	if timeoutSeconds <= 0 {
		timeoutSeconds = 300 // 5 minutes default
	}

	timeout := time.Duration(timeoutSeconds) * time.Second
	client := transport.NewSafeHTTPClient(ssrfOpts, timeout)

	return &HITLFilter{
		enabled:          enabled,
		destructiveTools: toolsMap,
		approvalMode:     approvalMode,
		webhookURL:       webhookURL,
		timeout:          timeout,
		httpClient:       client,
		ssrfOpts:         ssrfOpts,
	}
}

// SetCLIReaderWriter allows overriding CLI input/output (e.g. for unit testing).
func (h *HITLFilter) SetCLIReaderWriter(in io.Reader, out io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cliIn = in
	h.cliOut = out
}

// SetHITLDispatcher thread-safely binds the dual-channel HITL dispatcher to the filter.
func (h *HITLFilter) SetHITLDispatcher(dispatcher HITLApprover) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hitlDispatcher = dispatcher
}

// HITLDispatcher returns the currently configured dual-channel HITL dispatcher.
func (h *HITLFilter) HITLDispatcher() HITLApprover {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hitlDispatcher
}

// SetHTTPClient allows overriding the HTTP client (e.g. for unit testing).
func (h *HITLFilter) SetHTTPClient(client *http.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.httpClient = client
}

// Name returns the identifier of the filter.
func (h *HITLFilter) Name() string {
	return "hitl"
}

// Order returns the pipeline execution precedence (OrderHITL = 70).
func (h *HITLFilter) Order() int {
	return filter.OrderHITL
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (h *HITLFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := h.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (h *HITLFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return resp, nil
}

// FilterRequest intercepts destructive actions and waits for approval.
func (h *HITLFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if !h.enabled || req == nil || req.Method != "tools/call" {
		return req, nil
	}

	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return nil, mcp.NewError(mcp.ErrInvalidParams, "Invalid params in tools/call: "+err.Error(), nil)
	}

	// Check if the tool is registered as destructive (exact match or aggregated <protoSlug>__<tool> suffix)
	if !h.isDestructiveTool(callParams.Name) {
		return req, nil
	}

	// Respect Human Supremacy when an upstream filter already obtained explicit human approval.
	if types.IsHumanApproved(ctx) {
		return req, nil
	}

	// Extract user details
	userID := "unknown"
	if val := ctx.Value(types.UserContextKey); val != nil {
		if u, ok := val.(*types.UserContext); ok {
			userID = u.UserID
		}
	}

	slog.InfoContext(ctx, "Pausing execution of destructive tool, waiting for approval", slog.String("tool", callParams.Name), slog.String("user_id", userID))

	approved := false
	var err error

	h.mu.RLock()
	dispatcher := h.hitlDispatcher
	hasCustomCLI := h.cliIn != nil
	h.mu.RUnlock()

	if strings.EqualFold(h.approvalMode, "webhook") {
		if strings.TrimSpace(h.webhookURL) == "" {
			return nil, mcp.NewError(mcp.ErrHITLDenied, "Human-in-the-loop approval failed: webhook mode configured without webhook URL", nil)
		}
		approved, err = h.promptWebhook(ctx, callParams.Name, callParams.Arguments, userID)
	} else if dispatcher != nil && !hasCustomCLI {
		argsMap := make(map[string]interface{})
		if len(callParams.Arguments) > 0 {
			if uErr := json.Unmarshal(callParams.Arguments, &argsMap); uErr != nil {
				argsMap["raw"] = string(callParams.Arguments)
			}
		}
		waitCtx, cancel := context.WithTimeout(ctx, h.timeout)
		defer cancel()

		approved, err = dispatcher.RequestApproval(waitCtx, &hitltypes.HITLRequest{
			ToolName:       callParams.Name,
			Arguments:      argsMap,
			RiskScore:      1.0,
			ThreatDomain:   "DESTRUCTIVE_TOOL_POLICY",
			DecisionEngine: "hitl_filter",
		})
		if errors.Is(err, hitltypes.ErrHITLDenied) {
			err = nil
			approved = false
		}
	} else {
		// Standalone CLI console fallback
		approved, err = h.promptCLI(ctx, callParams.Name, string(callParams.Arguments))
	}

	if err != nil {
		return nil, mcp.NewError(mcp.ErrHITLDenied, "Human-in-the-loop approval failed: "+err.Error(), nil)
	}

	if !approved {
		return nil, mcp.NewError(mcp.ErrHITLDenied, fmt.Sprintf("Action denied: Destructive tool '%s' was rejected by safety operator", callParams.Name), nil)
	}

	types.SetHumanApproved(ctx, true)
	return req, nil
}

// FilterResponse passes through response payloads.
func (h *HITLFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	return resp, nil
}

func (h *HITLFilter) promptCLI(ctx context.Context, toolName string, args string) (bool, error) {
	h.mu.RLock()
	customIn := h.cliIn
	customOut := h.cliOut
	h.mu.RUnlock()

	if customIn != nil {
		out := customOut
		if out == nil {
			out = io.Discard
		}
		return h.awaitCLIApproval(ctx, out, toolName, args, func(waitCtx context.Context) (string, error) {
			return console.ReadLineFromReader(waitCtx, customIn)
		})
	}

	c, err := console.OpenInteractiveConsole()
	if err != nil {
		slog.WarnContext(ctx, "Cannot open interactive console, direct CLI confirmation is unavailable",
			slog.String("tool", toolName),
			slog.String("error", err.Error()),
		)
		return false, hitltypes.ErrHeadlessFailClosed
	}
	defer func() { _ = c.Close() }()

	return h.awaitCLIApproval(ctx, c, toolName, args, c.ReadLine)
}

func (h *HITLFilter) isDestructiveTool(name string) bool {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" {
		return false
	}
	if h.destructiveTools[norm] {
		return true
	}
	if _, tool, ok := strings.Cut(norm, "__"); ok && tool != "" {
		return h.destructiveTools[tool]
	}
	return false
}

func (h *HITLFilter) awaitCLIApproval(
	ctx context.Context,
	out io.Writer,
	toolName string,
	args string,
	readLine func(context.Context) (string, error),
) (bool, error) {
	safeTool := console.SanitizeTerminalText(toolName)
	safeArgs := console.SanitizeTerminalText(args)

	fmt.Fprintf(out, "\n🚨 [Farad Ai HITL] CRITICAL ACTION APPROVAL REQUESTED\n")
	fmt.Fprintf(out, "Tool Call: %s\n", safeTool)
	fmt.Fprintf(out, "Arguments: %s\n", safeArgs)
	fmt.Fprintf(out, "Approve execution? (y/N): ")

	waitCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	line, readErr := readLine(waitCtx)
	if readErr != nil {
		if errors.Is(readErr, context.DeadlineExceeded) && ctx.Err() == nil {
			fmt.Fprintf(out, "⏱️ Approval timed out (%v expired).\n\n", h.timeout)
			return false, hitltypes.ErrHITLTimeout
		}
		return false, readErr
	}

	if console.ParseYesNoAnswer(line) {
		fmt.Fprintf(out, "✅ Action approved.\n\n")
		return true, nil
	}
	fmt.Fprintf(out, "❌ Action rejected.\n\n")
	return false, nil
}

type webhookPayload struct {
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments"`
	UserID    string          `json:"user_id"`
}

type webhookResponse struct {
	Approved bool `json:"approved"`
}

func redactURLForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (h *HITLFilter) promptWebhook(ctx context.Context, toolName string, args json.RawMessage, userID string) (bool, error) {
	resolvedURL := os.ExpandEnv(h.webhookURL)
	safeLogURL := redactURLForLog(resolvedURL)
	if err := transport.ValidateURL(resolvedURL, h.ssrfOpts); err != nil {
		slog.WarnContext(ctx, "Webhook URL rejected by SSRF guardrails", slog.String("url", safeLogURL), slog.String("error", err.Error()))
		return false, fmt.Errorf("SSRF protection blocked webhook dispatch: %w", err)
	}

	payload := webhookPayload{
		ToolName:  toolName,
		Arguments: args,
		UserID:    userID,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	waitCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(waitCtx, "POST", resolvedURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("failed to construct webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	h.mu.RLock()
	httpClient := h.httpClient
	h.mu.RUnlock()

	resp, err := httpClient.Do(req)
	if err != nil {
		var uErr *url.Error
		if errors.As(err, &uErr) {
			return false, fmt.Errorf("webhook request failed: %w", uErr.Err)
		}
		return false, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}

	var webResp webhookResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&webResp); err != nil {
		return false, fmt.Errorf("failed to decode webhook response: %w", err)
	}

	return webResp.Approved, nil
}
