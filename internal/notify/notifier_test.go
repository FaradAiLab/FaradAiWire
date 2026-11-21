package notify

import (
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

func TestBuildAdminDashboardURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		host       string
		port       int
		tlsEnabled bool
		fragment   string
		want       string
	}{
		{
			name:     "loopback ipv4 http",
			host:     "127.0.0.1",
			port:     19415,
			fragment: "audit",
			want:     "http://127.0.0.1:19415/admin/dashboard#audit",
		},
		{
			name:     "empty host normalizes to loopback",
			host:     "",
			port:     19415,
			fragment: "guards",
			want:     "http://127.0.0.1:19415/admin/dashboard#guards",
		},
		{
			name:     "wildcard ipv4 0.0.0.0 normalizes to 127.0.0.1",
			host:     "0.0.0.0",
			port:     19415,
			fragment: "audit",
			want:     "http://127.0.0.1:19415/admin/dashboard#audit",
		},
		{
			name:       "wildcard ipv6 :: normalizes to [::1] with https",
			host:       "::",
			port:       19415,
			tlsEnabled: true,
			fragment:   "guards",
			want:       "https://[::1]:19415/admin/dashboard#guards",
		},
		{
			name:     "bracketed wildcard ipv6 [::] normalizes to [::1]",
			host:     "[::]",
			port:     19415,
			fragment: "audit",
			want:     "http://[::1]:19415/admin/dashboard#audit",
		},
		{
			name:     "ipv6 loopback ::1 uses brackets",
			host:     "::1",
			port:     19415,
			fragment: "guards",
			want:     "http://[::1]:19415/admin/dashboard#guards",
		},
		{
			name:     "localhost preserved",
			host:     "localhost",
			port:     8095,
			fragment: "#audit",
			want:     "http://localhost:8095/admin/dashboard#audit",
		},
		{
			name:     "custom host preserved",
			host:     "10.20.30.40",
			port:     19415,
			fragment: "audit",
			want:     "http://10.20.30.40:19415/admin/dashboard#audit",
		},
		{
			name:     "invalid fragment sanitized",
			host:     "127.0.0.1",
			port:     19415,
			fragment: "audit;rm -rf /",
			want:     "http://127.0.0.1:19415/admin/dashboard#auditrm-rf",
		},
		{
			name:     "zero port returns empty",
			host:     "127.0.0.1",
			port:     0,
			fragment: "audit",
			want:     "",
		},
		{
			name:     "out of range port returns empty",
			host:     "127.0.0.1",
			port:     70000,
			fragment: "audit",
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := BuildAdminDashboardURL(tc.host, tc.port, tc.tlsEnabled, tc.fragment)
			if got != tc.want {
				t.Fatalf("BuildAdminDashboardURL(%q, %d, %v, %q) = %q, want %q",
					tc.host, tc.port, tc.tlsEnabled, tc.fragment, got, tc.want)
			}
		})
	}
}

func TestValidateHTTPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "valid http", raw: "http://127.0.0.1:19415/admin/dashboard#audit", want: true},
		{name: "valid https ipv6", raw: "https://[::1]:19415/admin/dashboard#guards", want: true},
		{name: "empty", raw: "", want: false},
		{name: "javascript scheme rejected", raw: "javascript:alert(1)", want: false},
		{name: "file scheme rejected", raw: "file:///etc/passwd", want: false},
		{name: "control char rejected", raw: "http://127.0.0.1:19415/admin\n#audit", want: false},
		{name: "missing host rejected", raw: "http:///admin/dashboard", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidateHTTPURL(tc.raw); got != tc.want {
				t.Fatalf("ValidateHTTPURL(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCooldownTracker_PerCategoryIsolationAndHITLImmunity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	tracker := newCooldownTracker(func() time.Time { return now })

	// 1. GuardOffline consumes 60s cooldown for CategoryGuardOffline only.
	if !tracker.Allow(CategoryGuardOffline, 60*time.Second) {
		t.Fatal("expected initial GuardOffline alert to be allowed")
	}

	// 2. Same category within 60s is suppressed.
	now = now.Add(1 * time.Millisecond)
	if tracker.Allow(CategoryGuardOffline, 60*time.Second) {
		t.Fatal("expected duplicate GuardOffline alert within 60s to be suppressed")
	}

	// 3. Different categories (HITL and Block) are NOT starved by GuardOffline.
	if !tracker.Allow(CategoryHITLPending, 0) {
		t.Fatal("expected CategoryHITLPending to be allowed immediately after GuardOffline")
	}
	if !tracker.Allow(CategoryHITLPending, 0) {
		t.Fatal("expected repeated CategoryHITLPending to never be throttled")
	}
	if !tracker.Allow(CategoryBlock, 60*time.Second) {
		t.Fatal("expected CategoryBlock to be allowed independently of GuardOffline")
	}

	// 4. Advance clock 59s: GuardOffline still suppressed; at 60s: allowed.
	now = now.Add(59 * time.Second)
	if tracker.Allow(CategoryGuardOffline, 60*time.Second) {
		t.Fatal("expected GuardOffline to still be suppressed at 59.001s")
	}
	now = now.Add(1 * time.Second)
	if !tracker.Allow(CategoryGuardOffline, 60*time.Second) {
		t.Fatal("expected GuardOffline to be allowed at >=60s")
	}
}

func TestIsCategoryEnabled_SettingsCacheAndEnvOverrides(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "")

	// Default cache settings: offline/hitl/block=true, audit=false.
	op := settings.DefaultOperationalSettings()
	cache := settings.NewCache(op)

	if !isCategoryEnabled(CategoryGuardOffline, cache) {
		t.Error("expected CategoryGuardOffline enabled by default")
	}
	if !isCategoryEnabled(CategoryHITLPending, cache) {
		t.Error("expected CategoryHITLPending enabled by default")
	}
	if !isCategoryEnabled(CategoryBlock, cache) {
		t.Error("expected CategoryBlock enabled by default")
	}
	if isCategoryEnabled(CategoryAudit, cache) {
		t.Error("expected CategoryAudit disabled by default")
	}

	// Live cache update enables audit and disables block.
	updated := op.Clone()
	updated.Guard.AlertOnAudit = true
	updated.Guard.AlertOnBlock = false
	cache.Update(updated)

	if !isCategoryEnabled(CategoryAudit, cache) {
		t.Error("expected CategoryAudit enabled after cache update")
	}
	if isCategoryEnabled(CategoryBlock, cache) {
		t.Error("expected CategoryBlock disabled after cache update")
	}

	// Master toggle off disables all categories.
	masterOff := updated.Clone()
	masterOff.Guard.DesktopAlertsEnabled = false
	cache.Update(masterOff)
	if isCategoryEnabled(CategoryHITLPending, cache) {
		t.Error("expected CategoryHITLPending disabled when DesktopAlertsEnabled=false")
	}

	// Env hard-overrides always suppress even when cache says enabled.
	cache.Update(op)
	t.Setenv("CI", "true")
	if isCategoryEnabled(CategoryHITLPending, cache) {
		t.Error("expected CI=true hard override to suppress alerts")
	}
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	if isCategoryEnabled(CategoryGuardOffline, cache) {
		t.Error("expected GITHUB_ACTIONS=true hard override to suppress alerts")
	}
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "false")
	if isCategoryEnabled(CategoryGuardOffline, cache) {
		t.Error("expected FARADAI_ALERT_DESKTOP_ENABLED=false hard override to suppress alerts")
	}
}

func TestResolveCategoryCooldown(t *testing.T) {
	t.Setenv("FARADAI_ALERT_COOLDOWN_SEC", "")

	op := settings.DefaultOperationalSettings()
	cache := settings.NewCache(op)

	if got := resolveCategoryCooldown(CategoryHITLPending, cache); got != 0 {
		t.Fatalf("expected HITL cooldown 0, got %v", got)
	}
	if got := resolveCategoryCooldown(CategoryGuardOffline, cache); got != 60*time.Second {
		t.Fatalf("expected default cooldown 60s, got %v", got)
	}

	// Env override applies when cache cooldown is still baseline 60s.
	t.Setenv("FARADAI_ALERT_COOLDOWN_SEC", "15")
	if got := resolveCategoryCooldown(CategoryGuardOffline, cache); got != 15*time.Second {
		t.Fatalf("expected env cooldown 15s, got %v", got)
	}

	// Explicit cache override takes precedence over env override.
	custom := op.Clone()
	custom.Guard.AlertCooldownSec = 120
	cache.Update(custom)
	if got := resolveCategoryCooldown(CategoryBlock, cache); got != 120*time.Second {
		t.Fatalf("expected cache override 120s, got %v", got)
	}

	// Cache override to 0 disables throttling even if env is set.
	zero := op.Clone()
	zero.Guard.AlertCooldownSec = 0
	cache.Update(zero)
	if got := resolveCategoryCooldown(CategoryBlock, cache); got != 0 {
		t.Fatalf("expected cache override 0s, got %v", got)
	}
}
