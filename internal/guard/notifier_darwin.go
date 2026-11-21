//go:build darwin

package guard

import "github.com/FaradAiLab/FaradAiWire/internal/notify"

// DefaultCooldownDarwinNotification is the baseline debounce interval for
// direct guard fallback notifications.
const DefaultCooldownDarwinNotification = notify.DefaultCooldown

// ResetDarwinNotificationCooldown resets the fallback desktop notification cooldown timer.
func ResetDarwinNotificationCooldown() {
	notify.ResetCooldowns()
}

// NotifyDarwin dispatches a rate-limited macOS desktop alert routed to #guards.
func NotifyDarwin(title, message string) bool {
	return notify.NotifyDefault(notify.AlertEvent{
		Category:       notify.CategoryGuardOffline,
		Title:          title,
		Message:        message,
		TargetFragment: "guards",
	})
}
