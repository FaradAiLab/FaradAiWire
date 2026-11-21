package filter

import (
	"fmt"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/notify"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// AlertAuditLogger observes completed pipeline audit verdicts and translates
// actionable security decisions (blocks and opt-in audits) into desktop alerts
// routed to /admin/dashboard#audit without introducing filter-package cycles.
type AlertAuditLogger struct {
	notifier notify.DesktopNotifier
}

// Ensure AlertAuditLogger satisfies AuditLogger.
var _ AuditLogger = (*AlertAuditLogger)(nil)

// NewAlertAuditLogger constructs an AlertAuditLogger backed by the given DesktopNotifier.
func NewAlertAuditLogger(notifier notify.DesktopNotifier) *AlertAuditLogger {
	return &AlertAuditLogger{notifier: notifier}
}

// LogEvent translates actionable verdicts into desktop alert notifications.
// Messages contain only metadata (tool/method/filter/rule), never raw payloads.
func (a *AlertAuditLogger) LogEvent(event *AuditEvent) {
	if a == nil || a.notifier == nil || event == nil {
		return
	}

	subject := eventSubject(event)
	source := eventSource(event)

	switch normalizeDecisionName(event.Decision) {
	case DecisionBlocked, DecisionCritical:
		if isSuppressedHITLDenial(event) {
			return
		}
		a.notifier.Notify(notify.AlertEvent{
			Category:       notify.CategoryBlock,
			Title:          "FaradAiWire Request Blocked",
			Message:        fmt.Sprintf("Blocked %s via %s.", subject, source),
			TargetFragment: "audit",
		})

	case DecisionAudit:
		a.notifier.Notify(notify.AlertEvent{
			Category:       notify.CategoryAudit,
			Title:          "FaradAiWire Audit Match",
			Message:        fmt.Sprintf("Audit verdict on %s (%s).", subject, source),
			TargetFragment: "audit",
		})
	}
}

func isSuppressedHITLDenial(event *AuditEvent) bool {
	if event.ErrorCode != mcp.ErrHITLDenied {
		return false
	}
	msg := event.ErrorMessage
	if msg == "" {
		msg = event.Message
	}
	if strings.Contains(msg, hitltypes.ErrHeadlessFailClosed.Error()) ||
		strings.Contains(msg, "safety dispatcher unavailable") {
		return false
	}
	return true
}

func eventSubject(event *AuditEvent) string {
	if tool := strings.TrimSpace(event.ToolName); tool != "" {
		return fmt.Sprintf("tool '%s'", tool)
	}
	if method := strings.TrimSpace(event.Method); method != "" {
		return fmt.Sprintf("method '%s'", method)
	}
	return "request"
}

func eventSource(event *AuditEvent) string {
	if rule := strings.TrimSpace(event.MatchedRule); rule != "" {
		return rule
	}
	if len(event.AuditedRules) > 0 && strings.TrimSpace(event.AuditedRules[0]) != "" {
		return strings.TrimSpace(event.AuditedRules[0])
	}
	if filterName := strings.TrimSpace(event.FilterName); filterName != "" {
		return filterName
	}
	return "policy"
}
