//go:build darwin

package notify

import (
	"sync"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

type stubDarwinNotifier struct {
	mu            sync.RWMutex
	adminBaseURL  string
	settingsCache *settings.Cache
	cooldowns     *cooldownTracker
}

var defaultDarwinNotifier = newPlatformNotifier("", nil)

func newPlatformNotifier(adminBaseURL string, settingsCache *settings.Cache) DesktopNotifier {
	return &stubDarwinNotifier{
		adminBaseURL:  adminBaseURL,
		settingsCache: settingsCache,
		cooldowns:     newCooldownTracker(nil),
	}
}

func (n *stubDarwinNotifier) SetAdminBaseURL(baseURL string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.adminBaseURL = baseURL
}

func (n *stubDarwinNotifier) Notify(event AlertEvent) bool {
	if !isCategoryEnabled(event.Category, n.settingsCache) {
		return false
	}
	cooldown := resolveCategoryCooldown(event.Category, n.settingsCache)
	return n.cooldowns.Allow(event.Category, cooldown)
}

// NotifyDefault triggers a macOS desktop notification using package defaults.
func NotifyDefault(event AlertEvent) bool {
	return defaultDarwinNotifier.Notify(event)
}

// ResetCooldowns clears the package-default notification cooldown timers (primarily for testing).
func ResetCooldowns() {
	if dn, ok := defaultDarwinNotifier.(*stubDarwinNotifier); ok && dn.cooldowns != nil {
		dn.cooldowns.Reset()
	}
}
