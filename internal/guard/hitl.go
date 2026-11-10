package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/console"
)

var (
	// ErrHITLDenied indicates human-in-the-loop approval was denied by an operator.
	ErrHITLDenied = errors.New("human-in-the-loop approval denied")

	// ErrHITLTimeout indicates approval timed out after 60s without operator interaction.
	ErrHITLTimeout = errors.New("human-in-the-loop approval timed out after 60s without operator interaction")

	// ErrHeadlessFailClosed indicates approval failed-closed because no interactive channels are attached.
	ErrHeadlessFailClosed = errors.New("human-in-the-loop approval denied: headless environment with neither TTY nor Web Console attached")
)

// HITLRequest holds the payload and semantic risk metadata for human-in-the-loop review.
type HITLRequest struct {
	CallID         string                 `json:"call_id"`
	ToolName       string                 `json:"tool_name"`
	Arguments      map[string]interface{} `json:"arguments"`
	RiskScore      float64                `json:"risk_score"`
	ThreatDomain   string                 `json:"threat_domain"`
	CWE            string                 `json:"cwe"`
	DecisionEngine string                 `json:"decision_engine"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// WebSocketHub abstracts real-time event distribution and client presence for HITL escalations.
type WebSocketHub interface {
	Broadcast(event interface{})
	ClientCount() int
}

type pendingApproval struct {
	req      *HITLRequest
	respCh   chan bool
	resolved atomic.Bool
	approved atomic.Bool
}

// HITLDispatcherConfig provides tuning and channel bindings for the HITL safety engine.
type HITLDispatcherConfig struct {
	Timeout       time.Duration
	TTYIn         io.Reader
	TTYOut        io.Writer
	DisableTTY    bool
	AllowRESTOnly bool
	WSHub         WebSocketHub
}

// DefaultHITLDispatcherConfig provides the standard 60-second fail-closed configuration.
func DefaultHITLDispatcherConfig() HITLDispatcherConfig {
	return HITLDispatcherConfig{
		Timeout: 60 * time.Second,
	}
}

// HITLDispatcher coordinates dual-channel human verification across terminal TTY and Web Console.
type HITLDispatcher struct {
	cfg     HITLDispatcherConfig
	pending map[string]*pendingApproval
	mu      sync.RWMutex
}

// NewHITLDispatcher constructs an initialized HITLDispatcher.
func NewHITLDispatcher(cfg HITLDispatcherConfig) *HITLDispatcher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &HITLDispatcher{
		cfg:     cfg,
		pending: make(map[string]*pendingApproval),
	}
}

// SetWSHub dynamically updates or binds the WebSocket hub.
func (d *HITLDispatcher) SetWSHub(hub WebSocketHub) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.WSHub = hub
}

// HasAttachedChannel checks whether at least one interactive operator channel is attached.
func (d *HITLDispatcher) HasAttachedChannel() bool {
	d.mu.RLock()
	disableTTY := d.cfg.DisableTTY
	hasCustomTTY := d.cfg.TTYIn != nil && d.cfg.TTYOut != nil
	wsHub := d.cfg.WSHub
	d.mu.RUnlock()

	if isTTYAvailable(disableTTY, hasCustomTTY) {
		return true
	}
	if wsHub != nil && wsHub.ClientCount() > 0 {
		return true
	}
	return false
}

func isTTYAvailable(disableTTY, hasCustomTTY bool) bool {
	if disableTTY {
		return false
	}
	if hasCustomTTY {
		return true
	}
	// Probe whether an interactive console device is attached in the current OS environment.
	c, err := console.OpenInteractiveConsole()
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func generateCallID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("hitl-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("hitl-%s", hex.EncodeToString(bytes))
}

// RequestApproval broadcasts the tool call simultaneously across TTY and WebSocket,
// blocking until approved, denied, or timed out (fail-closed).
func (d *HITLDispatcher) RequestApproval(ctx context.Context, req *HITLRequest) (bool, error) {
	if req == nil {
		return false, errors.New("nil HITLRequest")
	}

	if req.CallID == "" {
		req.CallID = generateCallID()
	}

	d.mu.RLock()
	timeout := d.cfg.Timeout
	allowRESTOnly := d.cfg.AllowRESTOnly
	wsHub := d.cfg.WSHub
	ttyIn := d.cfg.TTYIn
	ttyOut := d.cfg.TTYOut
	disableTTY := d.cfg.DisableTTY
	d.mu.RUnlock()

	isTTYAvail := isTTYAvailable(disableTTY, ttyIn != nil && ttyOut != nil)
	hasChannel := isTTYAvail || (wsHub != nil && wsHub.ClientCount() > 0)

	// Enforce fail-closed safety in unattended headless environments (DEC-10)
	if !allowRESTOnly && !hasChannel {
		slog.WarnContext(ctx, "HITL escalation in headless environment: no operator attached, failing-closed",
			slog.String("call_id", req.CallID),
			slog.String("tool", req.ToolName),
		)
		return false, ErrHeadlessFailClosed
	}

	req.CreatedAt = time.Now()
	req.ExpiresAt = req.CreatedAt.Add(timeout)

	pa := &pendingApproval{
		req:    req,
		respCh: make(chan bool, 1),
	}

	d.mu.Lock()
	d.pending[req.CallID] = pa
	d.mu.Unlock()

	defer d.removePending(req.CallID)

	// 1. Broadcast to Web Console WebSocket channel
	if wsHub != nil {
		wsHub.Broadcast(map[string]interface{}{
			"type":            "HITL_APPROVAL_REQUIRED",
			"call_id":         req.CallID,
			"tool_name":       req.ToolName,
			"arguments":       req.Arguments,
			"risk_score":      req.RiskScore,
			"threat_domain":   req.ThreatDomain,
			"cwe":             req.CWE,
			"decision_engine": req.DecisionEngine,
			"created_at":      req.CreatedAt.Format(time.RFC3339),
			"expires_at":      req.ExpiresAt.Format(time.RFC3339),
		})
	}

	reqCtx, cancelPrompt := context.WithCancel(ctx)
	var promptDone chan struct{}

	// 2. Broadcast to local terminal console channel if attached
	if !disableTTY && isTTYAvail {
		promptDone = make(chan struct{})
		go d.promptTTY(reqCtx, req, pa, ttyIn, ttyOut, promptDone)
	}

	defer func() {
		cancelPrompt()
		if promptDone != nil {
			<-promptDone
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// 3. Await first response from either channel, or enforce 60s fail-closed expiration
	select {
	case approved := <-pa.respCh:
		if approved {
			slog.InfoContext(ctx, "HITL tool call approved by operator",
				slog.String("call_id", req.CallID),
				slog.String("tool", req.ToolName),
			)
			return true, nil
		}
		slog.WarnContext(ctx, "HITL tool call rejected by operator",
			slog.String("call_id", req.CallID),
			slog.String("tool", req.ToolName),
		)
		return false, ErrHITLDenied

	case <-timer.C:
		if pa.resolved.CompareAndSwap(false, true) {
			slog.WarnContext(ctx, "HITL tool call timed out after 60s: failing-closed",
				slog.String("call_id", req.CallID),
				slog.String("tool", req.ToolName),
			)
			d.broadcastResolution(req.CallID, false, "timeout")
		}
		return false, ErrHITLTimeout

	case <-ctx.Done():
		if pa.resolved.CompareAndSwap(false, true) {
			d.broadcastResolution(req.CallID, false, "cancelled")
		}
		return false, ctx.Err()
	}
}

// promptTTY renders the terminal prompt to the operator and captures y/N response.
func (d *HITLDispatcher) promptTTY(ctx context.Context, req *HITLRequest, pa *pendingApproval, customIn io.Reader, customOut io.Writer, promptDone chan struct{}) {
	if promptDone != nil {
		defer close(promptDone)
	}

	argsJSON, _ := json.Marshal(req.Arguments)
	riskPct := req.RiskScore * 100
	if riskPct == 0 && req.RiskScore > 0 {
		riskPct = req.RiskScore
	}

	prompt := fmt.Sprintf(
		"\n🚨 [Farad Ai Guard] SUSPICIOUS TOOL CALL DETECTED (Risk: %.0f%% - %s)\nTool: %s\nArgs: %s\nApprove execution? (y/N): ",
		riskPct,
		console.SanitizeTerminalText(req.ThreatDomain),
		console.SanitizeTerminalText(req.ToolName),
		console.SanitizeTerminalText(string(argsJSON)),
	)

	if customIn != nil && customOut != nil {
		_, _ = fmt.Fprint(customOut, prompt)
		answer, err := console.ReadLineFromReader(ctx, customIn)
		if err == nil {
			d.Resolve(req.CallID, console.ParseYesNoAnswer(answer))
		} else if errors.Is(err, context.Canceled) && pa.resolved.Load() {
			writeExternalResolutionNotice(customOut, pa.approved.Load())
		}
		return
	}

	c, err := console.OpenInteractiveConsole()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()

	_, _ = fmt.Fprint(c, prompt)

	line, err := c.ReadLine(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) && pa.resolved.Load() {
			writeExternalResolutionNotice(c, pa.approved.Load())
		}
		return
	}

	d.Resolve(req.CallID, console.ParseYesNoAnswer(line))
}

func writeExternalResolutionNotice(w io.Writer, approved bool) {
	if approved {
		_, _ = fmt.Fprint(w, "\n✅ Action approved via Web Console\n\n")
		return
	}
	_, _ = fmt.Fprint(w, "\n❌ Action rejected via Web Console\n\n")
}

// Resolve resolves a pending approval request by CallID.
// Returns true if successfully resolved, or false if not found or already resolved.
func (d *HITLDispatcher) Resolve(callID string, approved bool) bool {
	d.mu.RLock()
	pa, exists := d.pending[callID]
	d.mu.RUnlock()

	if !exists {
		return false
	}

	pa.approved.Store(approved)
	if !pa.resolved.CompareAndSwap(false, true) {
		return false
	}

	reason := "denied"
	if approved {
		reason = "approved"
	}
	d.broadcastResolution(callID, approved, reason)
	d.removePending(callID)
	pa.respCh <- approved
	return true
}

func (d *HITLDispatcher) removePending(callID string) {
	d.mu.Lock()
	delete(d.pending, callID)
	d.mu.Unlock()
}

func (d *HITLDispatcher) broadcastResolution(callID string, approved bool, reason string) {
	d.mu.RLock()
	hub := d.cfg.WSHub
	d.mu.RUnlock()

	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":     "HITL_RESOLVED",
			"call_id":  callID,
			"approved": approved,
			"reason":   reason,
		})
	}
}

// ListPending returns a snapshot of all currently unresolved approval requests.
func (d *HITLDispatcher) ListPending() []*HITLRequest {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make([]*HITLRequest, 0, len(d.pending))
	for _, pa := range d.pending {
		res = append(res, pa.req)
	}
	return res
}

// GetPending retrieves a specific unresolved approval request.
func (d *HITLDispatcher) GetPending(callID string) (*HITLRequest, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	pa, ok := d.pending[callID]
	if !ok {
		return nil, false
	}
	return pa.req, true
}
