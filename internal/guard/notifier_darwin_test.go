//go:build darwin

package guard

import "testing"

func TestNotifyDarwin_Cooldown(t *testing.T) {
	// Clear CI/host overrides so desktop alert logic is exercised deterministically even on CI runners.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")
	t.Setenv("FARADAI_ALERT_COOLDOWN_SEC", "60")
	ResetDarwinNotificationCooldown()

	// First call should trigger notification (returns true)
	first := NotifyDarwin("Test Title", "Test Message 1")
	if !first {
		t.Errorf("expected first call to trigger notification")
	}

	// Immediate second call should be suppressed by 60s cooldown (returns false)
	second := NotifyDarwin("Test Title", "Test Message 2")
	if second {
		t.Errorf("expected second call to be suppressed by cooldown")
	}

	// Reset cooldown allows subsequent notification
	ResetDarwinNotificationCooldown()
	third := NotifyDarwin("Test Title", "Test Message 3")
	if !third {
		t.Errorf("expected call after cooldown reset to trigger notification")
	}
}

func TestNotifyDarwin_ConfigurableOptions(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "")
	t.Setenv("FARADAI_ALERT_COOLDOWN_SEC", "60")
	ResetDarwinNotificationCooldown()

	// 1. When FARADAI_ALERT_DESKTOP_ENABLED is false, notification must be suppressed
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "false")
	if NotifyDarwin("Title", "Message") {
		t.Errorf("expected notification to be disabled when FARADAI_ALERT_DESKTOP_ENABLED=false")
	}

	// 2. When CI=true or GITHUB_ACTIONS=true, notification must be suppressed
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")
	t.Setenv("CI", "true")
	if NotifyDarwin("Title", "Message") {
		t.Errorf("expected notification to be disabled in CI environment")
	}
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	if NotifyDarwin("Title", "Message") {
		t.Errorf("expected notification to be disabled in GitHub Actions environment")
	}

	// 3. When enabled without CI, notification should trigger
	t.Setenv("GITHUB_ACTIONS", "")
	ResetDarwinNotificationCooldown()
	if !NotifyDarwin("Title", "Message") {
		t.Errorf("expected notification to trigger when enabled")
	}
}
