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
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/notify"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

var (
	// ErrHITLDenied indicates human-in-the-loop approval was denied by an operator.
	ErrHITLDenied = hitltypes.ErrHITLDenied

	// ErrHITLTimeout indicates approval timed out after 60s without operator interaction.
	ErrHITLTimeout = hitltypes.ErrHITLTimeout

	// ErrHeadlessFailClosed indicates approval failed-closed because no interactive channels are attached.
	ErrHeadlessFailClosed = hitltypes.ErrHeadlessFailClosed
)

// HITLRequest holds the payload and semantic risk metadata for human-in-the-loop review.
type HITLRequest = hitltypes.HITLRequest

// WebSocketHub abstracts real-time event distribution and client presence for HITL escalations.
type WebSocketHub interface {
	Broadcast(event interface{})
	ClientCount() int
}

const (
	hitlStatePending int32 = iota
	hitlStateApproved
	hitlStateDenied
	hitlStateTimeout
	hitlStateCancelled
)

type hitlDecision struct {
	approved bool
	channel  string
	actorID  string
	actorIP  string
	state    string
}

type pendingApproval struct {
	req    *HITLRequest
	respCh chan hitlDecision
	state  atomic.Int32
}

// HITLDispatcherConfig provides tuning and channel bindings for the HITL safety engine.
type HITLDispatcherConfig struct {
	Timeout         time.Duration
	TTYIn           io.Reader
	TTYOut          io.Writer
	DisableTTY      bool
	AllowRESTOnly   bool
	WSHub           WebSocketHub
	DesktopNotifier notify.DesktopNotifier
	SettingsCache   *settings.Cache
	OnResolved      func(hitltypes.HITLResolutionInfo)
}

// DefaultHITLDispatcherConfig provides the standard 60-second fail-closed configuration.
func DefaultHITLDispatcherConfig() HITLDispatcherConfig {
	return HITLDispatcherConfig{
		Timeout: 60 * time.Second,
	}
}

// HITLDispatcher coordinates dual-channel human verification across terminal TTY and Web Console.
type HITLDispatcher struct {
	cfg           HITLDispatcherConfig
	settingsCache *settings.Cache
	pending       map[string]*pendingApproval
	mu            sync.RWMutex
	ttySemOnce    sync.Once
	ttySem        chan struct{}
}

// NewHITLDispatcher constructs an initialized HITLDispatcher.
func NewHITLDispatcher(cfg HITLDispatcherConfig) *HITLDispatcher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &HITLDispatcher{
		cfg:           cfg,
		settingsCache: cfg.SettingsCache,
		pending:       make(map[string]*pendingApproval),
		ttySem:        make(chan struct{}, 1),
	}
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (d *HITLDispatcher) SetSettingsCache(c *settings.Cache) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.settingsCache = c
}

func resolveHITLTimeout(baseTimeout time.Duration, sCache *settings.Cache) time.Duration {
	timeout := baseTimeout
	if sCache != nil {
		if s := sCache.Get(); s != nil && s.Guard.HITLTimeoutSec > 0 {
			timeout = time.Duration(s.Guard.HITLTimeoutSec) * time.Second
		}
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return timeout
}

func (d *HITLDispatcher) acquireTTYSem(ctx context.Context) (func(), bool) {
	d.ttySemOnce.Do(func() {
		if d.ttySem == nil {
			d.ttySem = make(chan struct{}, 1)
		}
	})
	select {
	case d.ttySem <- struct{}{}:
		return func() { <-d.ttySem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// SetWSHub dynamically updates or binds the WebSocket hub.
func (d *HITLDispatcher) SetWSHub(hub WebSocketHub) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.WSHub = hub
}

// SetDesktopNotifier dynamically updates or binds the workstation desktop alert dispatcher.
func (d *HITLDispatcher) SetDesktopNotifier(notifier notify.DesktopNotifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.DesktopNotifier = notifier
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
	baseTimeout := d.cfg.Timeout
	sCache := d.settingsCache
	allowRESTOnly := d.cfg.AllowRESTOnly
	wsHub := d.cfg.WSHub
	ttyIn := d.cfg.TTYIn
	ttyOut := d.cfg.TTYOut
	disableTTY := d.cfg.DisableTTY
	desktopNotifier := d.cfg.DesktopNotifier
	d.mu.RUnlock()
	timeout := resolveHITLTimeout(baseTimeout, sCache)

	isTTYAvail := isTTYAvailable(disableTTY, ttyIn != nil && ttyOut != nil)
	hasChannel := isTTYAvail || (wsHub != nil && wsHub.ClientCount() > 0)

	// Enforce fail-closed safety in unattended headless environments (DEC-10)
	if !allowRESTOnly && !hasChannel {
		slog.WarnContext(ctx, "HITL escalation in headless environment: no operator attached, failing-closed",
			slog.String("call_id", req.CallID),
			slog.String("tool", req.ToolName),
		)
		req.ApprovedBy = "system:fail_closed"
		req.ApprovalChannel = "cli_tty"
		req.ResolutionState = "headless_fail_closed"
		d.notifyResolved(hitltypes.HITLResolutionInfo{
			CallID:          req.CallID,
			ToolName:        req.ToolName,
			Approved:        false,
			ApprovedBy:      "system:fail_closed",
			ApprovalChannel: "cli_tty",
			Outcome:         "denied",
			DecisionEngine:  req.DecisionEngine,
		})
		return false, ErrHeadlessFailClosed
	}

	req.CreatedAt = time.Now()
	req.ExpiresAt = req.CreatedAt.Add(timeout)

	pa := &pendingApproval{
		req:    req,
		respCh: make(chan hitlDecision, 1),
	}

	d.mu.Lock()
	d.pending[req.CallID] = pa
	d.mu.Unlock()

	defer d.removePending(req.CallID)

	// Notify workstation operator only after headless fail-closed checks pass and
	// the CallID is live in d.pending so clicking #audit displays an actionable modal.
	if desktopNotifier != nil {
		threatDomain := req.ThreatDomain
		if threatDomain == "" {
			threatDomain = "POLICY"
		}
		desktopNotifier.Notify(notify.AlertEvent{
			Category:       notify.CategoryHITLPending,
			Title:          "FaradAiWire HITL Approval Required",
			Message:        fmt.Sprintf("Tool '%s' awaiting operator confirmation (%s).", req.ToolName, threatDomain),
			TargetFragment: "audit",
		})
	}

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
	timeoutChannel := defaultTimeoutChannel(isTTYAvail, wsHub, allowRESTOnly)
	select {
	case dec := <-pa.respCh:
		req.ApprovedBy = dec.actorID
		req.ApprovalChannel = dec.channel
		req.ResolutionState = dec.state
		if dec.approved {
			slog.InfoContext(ctx, "HITL tool call approved by operator",
				slog.String("call_id", req.CallID),
				slog.String("tool", req.ToolName),
				slog.String("channel", dec.channel),
				slog.String("actor_id", dec.actorID),
			)
			return true, nil
		}
		slog.WarnContext(ctx, "HITL tool call rejected by operator",
			slog.String("call_id", req.CallID),
			slog.String("tool", req.ToolName),
			slog.String("channel", dec.channel),
			slog.String("actor_id", dec.actorID),
		)
		return false, ErrHITLDenied

	case <-timer.C:
		if pa.state.CompareAndSwap(hitlStatePending, hitlStateTimeout) {
			req.ApprovedBy = "system:timeout"
			req.ApprovalChannel = timeoutChannel
			req.ResolutionState = "timeout"
			slog.WarnContext(ctx, "HITL tool call timed out: failing-closed",
				slog.String("call_id", req.CallID),
				slog.String("tool", req.ToolName),
				slog.Duration("timeout", timeout),
				slog.String("channel", timeoutChannel),
			)
			d.broadcastResolution(req.CallID, false, "timeout")
			d.notifyResolved(hitltypes.HITLResolutionInfo{
				CallID:          req.CallID,
				ToolName:        req.ToolName,
				Approved:        false,
				ApprovedBy:      "system:timeout",
				ApprovalChannel: timeoutChannel,
				Outcome:         "timeout",
				DecisionEngine:  req.DecisionEngine,
			})
		} else {
			select {
			case dec := <-pa.respCh:
				req.ApprovedBy = dec.actorID
				req.ApprovalChannel = dec.channel
				req.ResolutionState = dec.state
				if dec.approved {
					return true, nil
				}
				return false, ErrHITLDenied
			default:
			}
		}
		return false, ErrHITLTimeout

	case <-ctx.Done():
		if pa.state.CompareAndSwap(hitlStatePending, hitlStateCancelled) {
			req.ApprovedBy = "system:cancelled"
			req.ApprovalChannel = timeoutChannel
			req.ResolutionState = "cancelled"
			d.broadcastResolution(req.CallID, false, "cancelled")
			d.notifyResolved(hitltypes.HITLResolutionInfo{
				CallID:          req.CallID,
				ToolName:        req.ToolName,
				Approved:        false,
				ApprovedBy:      "system:cancelled",
				ApprovalChannel: timeoutChannel,
				Outcome:         "cancelled",
				DecisionEngine:  req.DecisionEngine,
			})
		}
		return false, ctx.Err()
	}
}

// promptTTY renders the terminal prompt to the operator and captures y/N response.
func (d *HITLDispatcher) promptTTY(ctx context.Context, req *HITLRequest, pa *pendingApproval, customIn io.Reader, customOut io.Writer, promptDone chan struct{}) {
	if promptDone != nil {
		defer close(promptDone)
	}

	// Serialize concurrent TTY prompts without head-of-line blocking canceled or web-resolved requests.
	releaseTTY, acquired := d.acquireTTYSem(ctx)
	if !acquired {
		return
	}
	defer releaseTTY()

	if ctx.Err() != nil {
		return
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

	var out io.Writer
	var readFn func(context.Context) (string, error)
	if customIn != nil && customOut != nil {
		out = customOut
		readFn = func(readCtx context.Context) (string, error) {
			return console.ReadLineFromReader(readCtx, customIn)
		}
	} else {
		c, err := console.OpenInteractiveConsole()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		out = c
		readFn = c.ReadLine
	}

	_, _ = fmt.Fprint(out, prompt)

	line, err := readFn(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeExternalResolutionNotice(out, pa.state.Load())
		}
		return
	}

	d.ResolveWithContext(req.CallID, console.ParseYesNoAnswer(line), "cli_tty", "local-operator", "")
}

func writeExternalResolutionNotice(w io.Writer, state int32) {
	switch state {
	case hitlStateApproved:
		_, _ = fmt.Fprint(w, "\n✅ Action approved via Web Console\n\n")
	case hitlStateDenied:
		_, _ = fmt.Fprint(w, "\n❌ Action rejected via Web Console\n\n")
	case hitlStateTimeout:
		_, _ = fmt.Fprint(w, "\n⏱️ Action timed out without operator approval\n\n")
	}
}

// SetOnResolved attaches an optional callback fired once whenever an HITL request terminates.
func (d *HITLDispatcher) SetOnResolved(fn func(hitltypes.HITLResolutionInfo)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.OnResolved = fn
}

// HasOnResolved reports whether an OnResolved hook is currently configured on this dispatcher.
func (d *HITLDispatcher) HasOnResolved() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg.OnResolved != nil
}

func (d *HITLDispatcher) notifyResolved(info hitltypes.HITLResolutionInfo) {
	d.mu.RLock()
	fn := d.cfg.OnResolved
	d.mu.RUnlock()
	if fn != nil {
		fn(info)
	}
}

func defaultTimeoutChannel(isTTYAvail bool, wsHub WebSocketHub, allowRESTOnly bool) string {
	if wsHub != nil && wsHub.ClientCount() > 0 && !isTTYAvail {
		return "web_ws"
	}
	if isTTYAvail {
		return "cli_tty"
	}
	if allowRESTOnly {
		return "web_rest"
	}
	return "web_ws"
}

// Resolve resolves a pending approval request by CallID using default local operator provenance.
// Returns true if successfully resolved, or false if not found or already resolved.
func (d *HITLDispatcher) Resolve(callID string, approved bool) bool {
	return d.ResolveWithContext(callID, approved, "web_rest", "local-operator", "")
}

// ResolveWithProvenance resolves a pending approval request with explicit channel and actor attribution.
func (d *HITLDispatcher) ResolveWithProvenance(callID string, approved bool, channel, actorID string) bool {
	return d.ResolveWithContext(callID, approved, channel, actorID, "")
}

// ResolveWithContext resolves a pending approval request with explicit channel, actor ID, and source IP.
func (d *HITLDispatcher) ResolveWithContext(callID string, approved bool, channel, actorID, actorIP string) bool {
	d.mu.RLock()
	pa, exists := d.pending[callID]
	d.mu.RUnlock()

	if !exists {
		return false
	}

	if channel == "" {
		channel = "web_rest"
	}
	if actorID == "" {
		actorID = "local-operator"
	}

	targetState := hitlStateDenied
	stateStr := "denied"
	outcome := "denied"
	if approved {
		targetState = hitlStateApproved
		stateStr = "approved"
		outcome = "allowed"
	}
	if !pa.state.CompareAndSwap(hitlStatePending, targetState) {
		return false
	}

	d.broadcastResolution(callID, approved, stateStr)
	d.removePending(callID)
	d.notifyResolved(hitltypes.HITLResolutionInfo{
		CallID:          callID,
		ToolName:        pa.req.ToolName,
		Approved:        approved,
		ApprovedBy:      actorID,
		ApprovalChannel: channel,
		Outcome:         outcome,
		ActorIP:         actorIP,
		DecisionEngine:  pa.req.DecisionEngine,
	})
	pa.respCh <- hitlDecision{
		approved: approved,
		channel:  channel,
		actorID:  actorID,
		actorIP:  actorIP,
		state:    stateStr,
	}
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
