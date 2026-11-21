// Package notify provides platform-isolated, zero-I/O desktop security alert
// dispatching with per-category cooldowns and CSRF-safe Admin Console deep-linking.
package notify

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

// DefaultCooldown is the baseline rate-limiting window per non-HITL alert category.
const DefaultCooldown = 60 * time.Second

// AlertCategory classifies desktop security alerts for independent cooldowns
// and settings-driven enablement controls.
type AlertCategory string

const (
	// CategoryGuardOffline indicates Semantic Security Guard fell back to L1 regex protection.
	CategoryGuardOffline AlertCategory = "guard_offline"
	// CategoryHITLPending indicates an MCP tool call is awaiting human-in-the-loop approval.
	CategoryHITLPending AlertCategory = "hitl_pending"
	// CategoryBlock indicates the filter pipeline blocked an MCP tool request or response.
	CategoryBlock AlertCategory = "block"
	// CategoryAudit indicates a non-blocking ActionAudit rule matched (opt-in).
	CategoryAudit AlertCategory = "audit"
)

// AlertEvent describes a desktop notification payload and its target Admin Console hash route.
type AlertEvent struct {
	Category       AlertCategory
	Title          string
	Message        string
	TargetFragment string
}

// DesktopNotifier dispatches non-blocking workstation notifications that deep-link
// operators into the relevant Admin Console view.
type DesktopNotifier interface {
	Notify(event AlertEvent) bool
	SetAdminBaseURL(baseURL string)
}

// DefaultFragmentForCategory returns the canonical Admin Console hash route for a category.
func DefaultFragmentForCategory(cat AlertCategory) string {
	if cat == CategoryGuardOffline {
		return "guards"
	}
	return "audit"
}

// NewDesktopNotifier constructs a platform-specific DesktopNotifier bound to the
// given Admin Console base URL and zero-I/O operational settings cache.
func NewDesktopNotifier(adminBaseURL string, settingsCache *settings.Cache) DesktopNotifier {
	return newPlatformNotifier(adminBaseURL, settingsCache)
}

func envDesktopAlertDisabled() bool {
	if val := os.Getenv("FARADAI_ALERT_DESKTOP_ENABLED"); val != "" {
		lower := strings.ToLower(strings.TrimSpace(val))
		if lower == "false" || lower == "0" || lower == "off" || lower == "no" {
			return true
		}
	}
	if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
		return true
	}
	return false
}

func isCategoryEnabled(cat AlertCategory, cache *settings.Cache) bool {
	if envDesktopAlertDisabled() {
		return false
	}

	if cache != nil {
		if s := cache.Get(); s != nil {
			if !s.Guard.DesktopAlertsEnabled {
				return false
			}
			switch cat {
			case CategoryGuardOffline:
				return s.Guard.AlertOnGuardOffline
			case CategoryHITLPending:
				return s.Guard.AlertOnHITLPending
			case CategoryBlock:
				return s.Guard.AlertOnBlock
			case CategoryAudit:
				return s.Guard.AlertOnAudit
			default:
				return true
			}
		}
	}

	// Without an active settings cache, opt-in audit alerts stay off by default.
	return cat != CategoryAudit
}

func resolveCategoryCooldown(cat AlertCategory, cache *settings.Cache) time.Duration {
	if cat == CategoryHITLPending {
		return 0
	}

	defaultSec := int(DefaultCooldown / time.Second)
	if cache != nil {
		if s := cache.Get(); s != nil {
			if s.Guard.AlertCooldownSec != defaultSec {
				if s.Guard.AlertCooldownSec <= 0 {
					return 0
				}
				return time.Duration(s.Guard.AlertCooldownSec) * time.Second
			}
		}
	}

	if val := os.Getenv("FARADAI_ALERT_COOLDOWN_SEC"); val != "" {
		if sec, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sec >= 0 {
			return time.Duration(sec) * time.Second
		}
	}

	if cache != nil {
		if s := cache.Get(); s != nil && s.Guard.AlertCooldownSec >= 0 {
			return time.Duration(s.Guard.AlertCooldownSec) * time.Second
		}
	}

	return DefaultCooldown
}

type cooldownTracker struct {
	mu        sync.Mutex
	lastByCat map[AlertCategory]time.Time
	nowFn     func() time.Time
}

func newCooldownTracker(nowFn func() time.Time) *cooldownTracker {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &cooldownTracker{
		lastByCat: make(map[AlertCategory]time.Time),
		nowFn:     nowFn,
	}
}

func (c *cooldownTracker) Allow(cat AlertCategory, cooldown time.Duration) bool {
	if cooldown <= 0 {
		return true
	}

	now := c.nowFn()
	c.mu.Lock()
	defer c.mu.Unlock()

	if last, ok := c.lastByCat[cat]; ok && !last.IsZero() && now.Sub(last) < cooldown {
		return false
	}
	c.lastByCat[cat] = now
	return true
}

func (c *cooldownTracker) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.lastByCat)
}
