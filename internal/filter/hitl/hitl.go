package hitl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
)

// Ensure HITLFilter implements filter.SecurityFilter and filter.RequestFilter.
var (
	_ filter.SecurityFilter = (*HITLFilter)(nil)
	_ filter.RequestFilter  = (*HITLFilter)(nil)
)

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
}

// NewHITLFilter initializes a HITLFilter using default SSRF safe egress guardrails.
func NewHITLFilter(enabled bool, destructiveTools []string, approvalMode, webhookURL string, timeoutSeconds int) *HITLFilter {
	return NewHITLFilterWithSSRF(enabled, destructiveTools, approvalMode, webhookURL, timeoutSeconds, transport.DefaultSafeOptions())
}

// NewHITLFilterWithSSRF initializes a HITLFilter with explicit SSRF safe options.
func NewHITLFilterWithSSRF(enabled bool, destructiveTools []string, approvalMode, webhookURL string, timeoutSeconds int, ssrfOpts transport.SafeTransportOptions) *HITLFilter {
	toolsMap := make(map[string]bool)
	for _, t := range destructiveTools {
		toolsMap[t] = true
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
	h.cliIn = in
	h.cliOut = out
}

// SetHTTPClient allows overriding the HTTP client (e.g. for unit testing).
func (h *HITLFilter) SetHTTPClient(client *http.Client) {
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
	if !h.enabled || req.Method != "tools/call" {
		return req, nil
	}

	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return nil, mcp.NewError(mcp.ErrInvalidParams, "Invalid params in tools/call: "+err.Error(), nil)
	}

	// Check if the tool is registered as destructive
	if !h.destructiveTools[callParams.Name] {
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

	if h.approvalMode == "webhook" && h.webhookURL != "" {
		approved, err = h.promptWebhook(ctx, callParams.Name, callParams.Arguments, userID)
	} else {
		// Default to CLI prompt
		approved, err = h.promptCLI(ctx, callParams.Name, string(callParams.Arguments))
	}

	if err != nil {
		return nil, mcp.NewError(mcp.ErrHITLDenied, "Human-in-the-loop approval failed: "+err.Error(), nil)
	}

	if !approved {
		return nil, mcp.NewError(mcp.ErrHITLDenied, fmt.Sprintf("Action denied: Destructive tool '%s' was rejected by safety operator", callParams.Name), nil)
	}

	return req, nil
}

// FilterResponse passes through response payloads.
func (h *HITLFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	return resp, nil
}

func (h *HITLFilter) promptCLI(ctx context.Context, toolName string, args string) (bool, error) {
	var in io.Reader
	var out io.Writer
	var closer io.Closer

	if h.cliIn != nil {
		in = h.cliIn
		out = h.cliOut
		if out == nil {
			out = io.Discard
		}
	} else {
		// In UNIX/macOS, we can open /dev/tty to write to/read from the physical terminal
		// even if the standard input/output are redirected (piped JSON-RPC).
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			slog.WarnContext(ctx, "Cannot open /dev/tty, direct CLI confirmation is unavailable", slog.String("tool", toolName))
			return false, nil
		}
		closer = tty
		in = tty
		out = tty
	}
	if closer != nil {
		defer closer.Close()
	}

	fmt.Fprintf(out, "\n🚨 [Farad Ai HITL] CRITICAL ACTION APPROVAL REQUESTED\n")
	fmt.Fprintf(out, "Tool Call: %s\n", toolName)
	fmt.Fprintf(out, "Arguments: %s\n", args)
	fmt.Fprintf(out, "Approve execution? (y/N): ")

	reader := bufio.NewReader(in)
	inputCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		text, err := reader.ReadString('\n')
		if err != nil {
			errCh <- err
			return
		}
		inputCh <- strings.TrimSpace(strings.ToLower(text))
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case text := <-inputCh:
		if text == "y" || text == "yes" {
			fmt.Fprintf(out, "✅ Action approved.\n\n")
			return true, nil
		}
		fmt.Fprintf(out, "❌ Action rejected.\n\n")
		return false, nil
	case err := <-errCh:
		return false, err
	case <-time.After(h.timeout):
		fmt.Fprintf(out, "⏱️ Approval timed out (%v expired).\n\n", h.timeout)
		return false, fmt.Errorf("approval timeout")
	}
}

type webhookPayload struct {
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments"`
	UserID    string          `json:"user_id"`
}

type webhookResponse struct {
	Approved bool `json:"approved"`
}

func (h *HITLFilter) promptWebhook(ctx context.Context, toolName string, args json.RawMessage, userID string) (bool, error) {
	resolvedURL := os.ExpandEnv(h.webhookURL)
	if err := transport.ValidateURL(resolvedURL, h.ssrfOpts); err != nil {
		slog.WarnContext(ctx, "Webhook URL rejected by SSRF guardrails", slog.String("url", resolvedURL), slog.String("error", err.Error()))
		return false, fmt.Errorf("SSRF protection blocked webhook dispatch to '%s': %w", resolvedURL, err)
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

	req, err := http.NewRequestWithContext(ctx, "POST", resolvedURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}

	var webResp webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&webResp); err != nil {
		return false, fmt.Errorf("failed to decode webhook response: %w", err)
	}

	return webResp.Approved, nil
}
