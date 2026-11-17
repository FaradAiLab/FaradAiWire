//go:build darwin

package guard

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const osascriptDisplayNotification = `on run argv
display notification (item 1 of argv) with title (item 2 of argv) sound name "Ping"
end run`

var (
	lastDarwinNotification atomic.Int64                   // Unix timestamp in seconds
	darwinNotifySem        = make(chan struct{}, 4)       // Bound concurrent osascript subprocesses
)

// DefaultCooldownDarwinNotification is the baseline rate-limiting cooldown period for desktop alerts.
const DefaultCooldownDarwinNotification = 60 * time.Second

// ResetDarwinNotificationCooldown resets the cooldown timer (primarily for testing).
func ResetDarwinNotificationCooldown() {
	lastDarwinNotification.Store(0)
}

// getNotificationCooldown returns the configured or default cooldown duration.
func getNotificationCooldown() time.Duration {
	if val := os.Getenv("FARADAI_ALERT_COOLDOWN_SEC"); val != "" {
		if sec, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sec >= 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return DefaultCooldownDarwinNotification
}

// isDesktopAlertEnabled checks environment variables to determine whether desktop alerts are enabled.
func isDesktopAlertEnabled() bool {
	// Explicit disable via env
	if val := os.Getenv("FARADAI_ALERT_DESKTOP_ENABLED"); val != "" {
		lower := strings.ToLower(strings.TrimSpace(val))
		if lower == "false" || lower == "0" || lower == "off" || lower == "no" {
			return false
		}
	}
	// Headless CI environments
	if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
		return false
	}
	return true
}

// NotifyDarwin triggers a native macOS desktop notification via AppleScript osascript.
// It is non-blocking and enforces a rate-limiting cooldown (default 60s, configurable via FARADAI_ALERT_COOLDOWN_SEC).
func NotifyDarwin(title, message string) bool {
	if !isDesktopAlertEnabled() {
		return false
	}

	cooldown := getNotificationCooldown()
	cooldownSec := int64(cooldown / time.Second)

	now := time.Now().Unix()
	for {
		last := lastDarwinNotification.Load()
		if cooldownSec > 0 && last > 0 && now-last < cooldownSec {
			return false
		}
		if lastDarwinNotification.CompareAndSwap(last, now) {
			break
		}
	}

	// Launch asynchronously with bounded concurrency and timeout to prevent caller blocking or goroutine buildup.
	select {
	case darwinNotifySem <- struct{}{}:
		go func(msg, ttl string) {
			defer func() { <-darwinNotifySem }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Pass message and title via argv so untrusted text cannot alter AppleScript syntax.
			cmd := exec.CommandContext(ctx, "osascript", "-e", osascriptDisplayNotification, msg, ttl)
			if err := cmd.Run(); err != nil {
				slog.Debug("macOS desktop notification invocation failed",
					slog.String("error", err.Error()),
					slog.String("title", ttl),
				)
			}
		}(message, title)
	default:
		slog.Debug("macOS desktop notification skipped: concurrent notification limit reached",
			slog.String("title", title),
		)
	}

	return true
}
