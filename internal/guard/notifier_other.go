//go:build !darwin

package guard

import "github.com/FaradAiLab/FaradAiWire/internal/notify"

// ResetDarwinNotificationCooldown is a no-op on non-darwin platforms.
func ResetDarwinNotificationCooldown() {
	notify.ResetCooldowns()
}

// NotifyDarwin delegates to notify.NotifyDefault (no-op on non-darwin platforms).
func NotifyDarwin(title, message string) bool {
	return notify.NotifyDefault(notify.AlertEvent{
		Category:       notify.CategoryGuardOffline,
		Title:          title,
		Message:        message,
		TargetFragment: "guards",
	})
}
