//go:build !darwin

package notify

import "github.com/FaradAiLab/FaradAiWire/internal/settings"

type noopNotifier struct{}

func newPlatformNotifier(_ string, _ *settings.Cache) DesktopNotifier {
	return noopNotifier{}
}

func (noopNotifier) Notify(_ AlertEvent) bool {
	return false
}

func (noopNotifier) SetAdminBaseURL(_ string) {}

func (noopNotifier) AdminBaseURL() string {
	return ""
}

// NotifyDefault triggers a platform desktop notification using package defaults.
// It is a no-op on non-Darwin platforms.
func NotifyDefault(_ AlertEvent) bool {
	return false
}

// ResetCooldowns clears package-default notification cooldown timers.
// It is a no-op on non-Darwin platforms.
func ResetCooldowns() {}
