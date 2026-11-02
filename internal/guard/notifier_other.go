//go:build !darwin

package guard

// ResetDarwinNotificationCooldown is a no-op on non-darwin platforms.
func ResetDarwinNotificationCooldown() {}

// NotifyDarwin is a no-op on non-darwin platforms.
func NotifyDarwin(title, message string) bool {
	return false
}
