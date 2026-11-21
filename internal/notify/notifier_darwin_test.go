//go:build darwin

package notify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

type recordedCmd struct {
	name string
	args []string
}

func TestDarwinNotifier_TestingGuardSuppressesSubprocess(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	// Default darwinNotifier has runner == nil; testing.Testing() must short-circuit
	// without spawning OS subprocesses or mutating ~/.faradaiwire.
	n := NewDesktopNotifier("http://127.0.0.1:19415", nil)
	if !n.Notify(AlertEvent{
		Category:       CategoryGuardOffline,
		Title:          "FaradAiWire Security Alert",
		Message:        "Semantic Guard is offline; L1 regex fallback active.",
		TargetFragment: "guards",
	}) {
		t.Fatal("expected Notify to return true under testing.Testing() guard")
	}
}

func TestDarwinNotifier_Tier1TerminalNotifierWithEscaping(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	ch := make(chan recordedCmd, 1)
	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		lookPath: func(bin string) (string, error) {
			if bin == "terminal-notifier" {
				return "/opt/homebrew/bin/terminal-notifier", nil
			}
			return "", errors.New("not found")
		},
		runner: func(_ context.Context, name string, args ...string) error {
			ch <- recordedCmd{name: name, args: slices.Clone(args)}
			return nil
		},
	}

	ok := n.Notify(AlertEvent{
		Category:       CategoryBlock,
		Title:          "[FaradAiWire] Blocked",
		Message:        "-policy violated",
		TargetFragment: "audit",
	})
	if !ok {
		t.Fatal("expected Notify to return true")
	}

	select {
	case cmd := <-ch:
		if cmd.name != "/opt/homebrew/bin/terminal-notifier" {
			t.Fatalf("expected terminal-notifier binary, got %q", cmd.name)
		}
		joined := strings.Join(cmd.args, " | ")
		if !slices.Contains(cmd.args, `\[FaradAiWire] Blocked`) {
			t.Errorf("expected escaped leading '[' in title, got args: %s", joined)
		}
		if !slices.Contains(cmd.args, `\-policy violated`) {
			t.Errorf("expected escaped leading '-' in message, got args: %s", joined)
		}
		if !slices.Contains(cmd.args, "http://127.0.0.1:19415/admin/dashboard#audit") {
			t.Errorf("expected -open target URL in args, got: %s", joined)
		}
		if !slices.Contains(cmd.args, "faradaiwire-block") {
			t.Errorf("expected category group in args, got: %s", joined)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 1 command invocation")
	}
}

func TestDarwinNotifier_Tier2HelperAppMaterializationAndClickURL(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	var mu sync.Mutex
	var cmds []recordedCmd
	done := make(chan struct{}, 1)

	n := &darwinNotifier{
		adminBaseURL:  BuildAdminBaseURL("0.0.0.0", 19415, false),
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not installed") },
		runner: func(_ context.Context, name string, args ...string) error {
			mu.Lock()
			cmds = append(cmds, recordedCmd{name: name, args: slices.Clone(args)})
			mu.Unlock()

			// Simulate osacompile creating the bundle directory layout so atomic rename succeeds.
			if name == "/usr/bin/osacompile" {
				for i := 0; i < len(args)-1; i++ {
					if args[i] == "-o" {
						appDir := args[i+1]
						if err := os.MkdirAll(filepath.Join(appDir, "Contents", "MacOS"), 0o755); err != nil {
							return err
						}
						if err := os.WriteFile(filepath.Join(appDir, "Contents", "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
							return err
						}
						if err := os.WriteFile(filepath.Join(appDir, "Contents", "MacOS", "applet"), []byte("bin"), 0o755); err != nil {
							return err
						}
					}
				}
			}
			if name == "/usr/bin/open" {
				select {
				case done <- struct{}{}:
				default:
				}
			}
			return nil
		},
	}

	if !n.Notify(AlertEvent{
		Category:       CategoryGuardOffline,
		Title:          "FaradAiWire Security Alert",
		Message:        "Semantic Guard is offline;\nL1 regex fallback active.",
		TargetFragment: "guards",
	}) {
		t.Fatal("expected Notify to return true")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 2 open invocation")
	}

	mu.Lock()
	defer mu.Unlock()

	var sawOsacompile, sawPlutil, sawCodesign, sawOpen bool
	for _, c := range cmds {
		switch c.name {
		case "/usr/bin/osacompile":
			sawOsacompile = true
		case "/usr/bin/plutil":
			if slices.Contains(c.args, "LSUIElement") {
				sawPlutil = true
			}
		case "/usr/bin/codesign":
			sawCodesign = true
		case "/usr/bin/open":
			sawOpen = true
			if !slices.Contains(c.args, "-g") || !slices.Contains(c.args, "-W") {
				t.Errorf("expected open -W -g flags, got: %v", c.args)
			}
		}
	}
	if !sawOsacompile || !sawPlutil || !sawCodesign || !sawOpen {
		t.Fatalf("missing expected Tier 2 steps: osacompile=%v plutil=%v codesign=%v open=%v",
			sawOsacompile, sawPlutil, sawCodesign, sawOpen)
	}

	urlBytes, err := os.ReadFile(filepath.Join(home, ".faradaiwire", "notifier", "last_alert_url.txt"))
	if err != nil {
		t.Fatalf("expected last_alert_url.txt: %v", err)
	}
	if strings.TrimSpace(string(urlBytes)) != "http://127.0.0.1:19415/admin/dashboard#guards" {
		t.Fatalf("unexpected last_alert_url.txt: %q", string(urlBytes))
	}

	pendingBytes, err := os.ReadFile(filepath.Join(home, ".faradaiwire", "notifier", "pending_alert.txt"))
	if err != nil {
		t.Fatalf("expected pending_alert.txt: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(pendingBytes), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 lines in pending_alert.txt (newlines sanitized), got %d: %q", len(lines), string(pendingBytes))
	}
}

func TestDarwinNotifier_Tier3FallbackOnHelperFailureAndConcurrency(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	ch := make(chan recordedCmd, 10)

	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not installed") },
		runner: func(_ context.Context, name string, args ...string) error {
			if name == "/usr/bin/osacompile" {
				return errors.New("mdm blocked osacompile")
			}
			ch <- recordedCmd{name: name, args: slices.Clone(args)}
			return nil
		},
	}

	// Fire 4 concurrent HITL alerts (0s cooldown) to verify -race safety and Tier 3 fallback.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.Notify(AlertEvent{
				Category:       CategoryHITLPending,
				Title:          "FaradAiWire HITL",
				Message:        "Approval required",
				TargetFragment: "audit",
			})
		}()
	}
	wg.Wait()

	for i := 0; i < 4; i++ {
		select {
		case cmd := <-ch:
			if cmd.name != "/usr/bin/osascript" {
				t.Fatalf("expected Tier 3 fallback to /usr/bin/osascript, got %q", cmd.name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for Tier 3 fallback #%d", i)
		}
	}
}

func simulateOsacompileBundle(name string, args []string) error {
	if name != "/usr/bin/osacompile" {
		return nil
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-o" {
			appDir := args[i+1]
			if err := os.MkdirAll(filepath.Join(appDir, "Contents", "MacOS"), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(appDir, "Contents", "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(appDir, "Contents", "MacOS", "applet"), []byte("bin"), 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestDarwinNotifier_SemaphoreBackpressureNonBlocking(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	started := make(chan struct{}, 4)
	release := make(chan struct{})
	finished := make(chan struct{}, 5)

	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		lookPath: func(bin string) (string, error) {
			if bin == "terminal-notifier" {
				return "/opt/homebrew/bin/terminal-notifier", nil
			}
			return "", errors.New("not found")
		},
		runner: func(_ context.Context, _ string, _ ...string) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			finished <- struct{}{}
			return nil
		},
	}

	// Fill all 4 semaphore slots cleanly with HITL alerts (0s cooldown).
	for i := 0; i < 4; i++ {
		if !n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "m", TargetFragment: "audit"}) {
			t.Fatalf("slot %d should have been accepted", i)
		}
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for runner slot %d to start", i)
		}
	}

	// 5th concurrent Notify must drop non-blockingly and return false.
	doneNonBlock := make(chan bool, 1)
	go func() {
		doneNonBlock <- n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "dropped", TargetFragment: "audit"})
	}()
	select {
	case accepted := <-doneNonBlock:
		if accepted {
			t.Fatal("expected 5th concurrent Notify to return false under full semaphore backpressure")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Notify blocked under semaphore pressure")
	}

	// Unblock the 4 workers and verify semaphore recovers for subsequent alerts.
	close(release)
	for i := 0; i < 4; i++ {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for blocked runner %d to exit", i)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(n.sem) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "recovered", TargetFragment: "audit"}) {
		t.Fatal("expected Notify to succeed once semaphore drained")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for recovered Notify dispatch")
	}
}

func TestDarwinNotifier_Tier1FailureFallsBackToTier2(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	var mu sync.Mutex
	var cmds []recordedCmd
	openDone := make(chan struct{}, 1)

	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath: func(bin string) (string, error) {
			if bin == "terminal-notifier" {
				return "/opt/homebrew/bin/terminal-notifier", nil
			}
			return "", errors.New("not found")
		},
		runner: func(_ context.Context, name string, args ...string) error {
			mu.Lock()
			cmds = append(cmds, recordedCmd{name: name, args: slices.Clone(args)})
			mu.Unlock()

			if name == "/opt/homebrew/bin/terminal-notifier" {
				return errors.New("terminal-notifier launch failed")
			}
			if err := simulateOsacompileBundle(name, args); err != nil {
				return err
			}
			if name == "/usr/bin/open" {
				select {
				case openDone <- struct{}{}:
				default:
				}
			}
			return nil
		},
	}

	if !n.Notify(AlertEvent{Category: CategoryBlock, Title: "Blocked", Message: "Tool denied", TargetFragment: "audit"}) {
		t.Fatal("expected Notify to accept dispatch")
	}
	select {
	case <-openDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 2 open fallback")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(cmds) < 5 {
		t.Fatalf("expected terminal-notifier + osacompile + plutil + codesign + open, got %d cmds: %+v", len(cmds), cmds)
	}
	if cmds[0].name != "/opt/homebrew/bin/terminal-notifier" {
		t.Fatalf("expected Tier 1 attempted first, got %q", cmds[0].name)
	}
	for _, c := range cmds {
		if c.name == "/usr/bin/osascript" {
			t.Fatal("did not expect Tier 3 osascript when Tier 2 fallback succeeded")
		}
	}
}

func TestDarwinNotifier_Tier2ReusesCurrentHelperAndUpgradesStaleVersion(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	// 1. Pre-seeded matching version skips osacompile/plutil/codesign and calls open directly.
	homeCurrent := t.TempDir()
	baseCurrent := filepath.Join(homeCurrent, ".faradaiwire", "notifier")
	appCurrent := filepath.Join(baseCurrent, "FaradAiWireNotifier.app")
	if err := os.MkdirAll(filepath.Join(appCurrent, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appCurrent, "Contents", "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appCurrent, "Contents", "MacOS", "applet"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseCurrent, ".applet-version"), []byte(notifierAppletVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu1 sync.Mutex
	var cmds1 []recordedCmd
	done1 := make(chan struct{}, 1)
	n1 := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return homeCurrent, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not found") },
		runner: func(_ context.Context, name string, args ...string) error {
			mu1.Lock()
			cmds1 = append(cmds1, recordedCmd{name: name, args: slices.Clone(args)})
			mu1.Unlock()
			if name == "/usr/bin/open" {
				done1 <- struct{}{}
			}
			return nil
		},
	}

	n1.Notify(AlertEvent{Category: CategoryBlock, Title: "Reuse", Message: "Reused helper", TargetFragment: "audit"})
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for open on cached helper")
	}

	mu1.Lock()
	if len(cmds1) != 1 || cmds1[0].name != "/usr/bin/open" {
		mu1.Unlock()
		t.Fatalf("expected only /usr/bin/open when helper matches version %s, got: %+v", notifierAppletVersion, cmds1)
	}
	mu1.Unlock()

	// 2. Stale .applet-version ("0") forces rebuild + atomic swapAppBundle without leaving .bak.
	homeStale := t.TempDir()
	baseStale := filepath.Join(homeStale, ".faradaiwire", "notifier")
	appStale := filepath.Join(baseStale, "FaradAiWireNotifier.app")
	if err := os.MkdirAll(filepath.Join(appStale, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appStale, "Contents", "Info.plist"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appStale, "Contents", "MacOS", "applet"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseStale, ".applet-version"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	done2 := make(chan struct{}, 1)
	var sawOsacompile atomic.Bool
	n2 := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return homeStale, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not found") },
		runner: func(_ context.Context, name string, args ...string) error {
			if name == "/usr/bin/osacompile" {
				sawOsacompile.Store(true)
			}
			if err := simulateOsacompileBundle(name, args); err != nil {
				return err
			}
			if name == "/usr/bin/open" {
				done2 <- struct{}{}
			}
			return nil
		},
	}

	n2.Notify(AlertEvent{Category: CategoryBlock, Title: "Upgrade", Message: "Upgraded helper", TargetFragment: "audit"})
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for helper upgrade open")
	}

	if !sawOsacompile.Load() {
		t.Fatal("expected stale applet version to trigger rebuild")
	}
	verData, err := os.ReadFile(filepath.Join(baseStale, ".applet-version"))
	if err != nil || strings.TrimSpace(string(verData)) != notifierAppletVersion {
		t.Fatalf("expected upgraded .applet-version %q, got %q (err=%v)", notifierAppletVersion, string(verData), err)
	}
	if _, err := os.Stat(appStale + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected backup bundle to be cleaned up, stat err=%v", err)
	}
}

func TestDarwinNotifier_DefaultFragmentAndEmptyBaseURLClearsStaleURL(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	baseDir := filepath.Join(home, ".faradaiwire", "notifier")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "last_alert_url.txt"), []byte("http://stale.example/old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	openDone := make(chan struct{}, 2)
	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not found") },
		runner: func(_ context.Context, name string, args ...string) error {
			if err := simulateOsacompileBundle(name, args); err != nil {
				return err
			}
			if name == "/usr/bin/open" {
				openDone <- struct{}{}
			}
			return nil
		},
	}

	// 1. Empty TargetFragment falls back to DefaultFragmentForCategory (#audit for CategoryBlock).
	if !n.Notify(AlertEvent{Category: CategoryBlock, Title: "Block", Message: "Default fragment check"}) {
		t.Fatal("expected Notify to succeed")
	}
	select {
	case <-openDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first Tier 2 open")
	}
	gotURL, err := os.ReadFile(filepath.Join(baseDir, "last_alert_url.txt"))
	if err != nil || strings.TrimSpace(string(gotURL)) != "http://127.0.0.1:19415/admin/dashboard#audit" {
		t.Fatalf("got URL %q (err=%v), want default #audit URL", string(gotURL), err)
	}

	// 2. Empty AdminBaseURL overwrites/truncates stale last_alert_url.txt cleanly.
	n.SetAdminBaseURL("")
	if !n.Notify(AlertEvent{Category: CategoryGuardOffline, Title: "Offline", Message: "Cleared URL check"}) {
		t.Fatal("expected Notify to succeed after clearing base URL")
	}
	select {
	case <-openDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second Tier 2 open")
	}
	gotCleared, err := os.ReadFile(filepath.Join(baseDir, "last_alert_url.txt"))
	if err != nil {
		t.Fatalf("read last_alert_url.txt: %v", err)
	}
	if len(gotCleared) != 0 {
		t.Fatalf("expected last_alert_url.txt to be cleared when AdminBaseURL is empty, got %q", string(gotCleared))
	}
}

func TestNotifyDefault_AndResetCooldowns(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")
	t.Setenv("FARADAI_ALERT_COOLDOWN_SEC", "60")

	ResetCooldowns()
	t.Cleanup(ResetCooldowns)

	ev := AlertEvent{
		Category:       CategoryGuardOffline,
		Title:          "FaradAiWire Security Alert",
		Message:        "Package default check",
		TargetFragment: "guards",
	}
	if !NotifyDefault(ev) {
		t.Fatal("expected first NotifyDefault to succeed under testing.Testing() guard")
	}
	if NotifyDefault(ev) {
		t.Fatal("expected immediate repeat NotifyDefault to be throttled")
	}
	ResetCooldowns()
	if !NotifyDefault(ev) {
		t.Fatal("expected NotifyDefault immediately after ResetCooldowns() to succeed")
	}
}

func TestDarwinNotifier_SymlinkBaseDirRejected(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	evilTarget := t.TempDir()
	faradaiDir := filepath.Join(home, ".faradaiwire")
	if err := os.MkdirAll(faradaiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evilTarget, filepath.Join(faradaiDir, "notifier")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	osascriptCalled := make(chan struct{}, 1)
	var osacompileCalled atomic.Bool
	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not found") },
		runner: func(_ context.Context, name string, _ ...string) error {
			if name == "/usr/bin/osacompile" {
				osacompileCalled.Store(true)
			}
			if name == "/usr/bin/osascript" {
				select {
				case osascriptCalled <- struct{}{}:
				default:
				}
			}
			return nil
		},
	}

	if !n.Notify(AlertEvent{Category: CategoryBlock, Title: "Symlink", Message: "Symlink guard", TargetFragment: "audit"}) {
		t.Fatal("expected Notify to fall back to Tier 3 when Tier 2 symlink dir is rejected")
	}
	select {
	case <-osascriptCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 3 fallback after symlink dir rejection")
	}
	if osacompileCalled.Load() {
		t.Fatal("expected osacompile not to run when notifier directory is a symlink")
	}
}

func TestDarwinNotifier_HelperBuildRetriesAfterBackoff(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	home := t.TempDir()
	var clockMu sync.Mutex
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	var compileAttempts atomic.Int32
	var shouldFailBuild atomic.Bool
	shouldFailBuild.Store(true)

	osascriptDone := make(chan struct{}, 2)
	openDone := make(chan struct{}, 1)

	n := &darwinNotifier{
		adminBaseURL:  "http://127.0.0.1:19415",
		settingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, 4),
		homeDir:       func() (string, error) { return home, nil },
		lookPath:      func(string) (string, error) { return "", errors.New("not found") },
		nowFn: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
		runner: func(_ context.Context, name string, args ...string) error {
			if name == "/usr/bin/osacompile" {
				compileAttempts.Add(1)
				if shouldFailBuild.Load() {
					return errors.New("transient build failure")
				}
				return simulateOsacompileBundle(name, args)
			}
			if name == "/usr/bin/osascript" {
				osascriptDone <- struct{}{}
			}
			if name == "/usr/bin/open" {
				openDone <- struct{}{}
			}
			return nil
		},
	}

	// 1. Initial failure records helperErr and falls back to Tier 3.
	n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "Try 1", TargetFragment: "audit"})
	select {
	case <-osascriptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 3 after initial failure")
	}
	if compileAttempts.Load() != 1 {
		t.Fatalf("expected 1 compile attempt, got %d", compileAttempts.Load())
	}

	// 2. Before backoff expires, cached error short-circuits without retrying osacompile.
	n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "Try 2", TargetFragment: "audit"})
	select {
	case <-osascriptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cached Tier 3 fallback")
	}
	if compileAttempts.Load() != 1 {
		t.Fatalf("expected cached backoff to skip osacompile, got %d attempts", compileAttempts.Load())
	}

	// 3. Advance clock past helperBuildRetryBackoff and allow build to succeed.
	clockMu.Lock()
	now = now.Add(helperBuildRetryBackoff + time.Second)
	clockMu.Unlock()
	shouldFailBuild.Store(false)

	n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "Try 3", TargetFragment: "audit"})
	select {
	case <-openDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Tier 2 recovery after backoff expiry")
	}
	if compileAttempts.Load() != 2 {
		t.Fatalf("expected second compile attempt after backoff, got %d", compileAttempts.Load())
	}
}

func TestDarwinNotifier_CloseDrainsInFlight(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	n := newDarwinNotifier("http://127.0.0.1:19415", settings.NewCache(settings.DefaultOperationalSettings()))
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	n.lookPath = func(bin string) (string, error) {
		if bin == "terminal-notifier" {
			return "/opt/homebrew/bin/terminal-notifier", nil
		}
		return "", errors.New("not found")
	}
	n.runner = func(ctx context.Context, _ string, _ ...string) error {
		started <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		return ctx.Err()
	}

	if !n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "In-flight", TargetFragment: "audit"}) {
		t.Fatal("expected Notify to start worker")
	}
	<-started

	closeDone := make(chan struct{})
	go func() {
		n.Close()
		close(closeDone)
	}()

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("expected Close() to cancel in-flight worker context")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("expected Close() to return once worker drained")
	}

	if n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "After close", TargetFragment: "audit"}) {
		t.Fatal("expected Notify after Close() to return false")
	}
}

func TestDarwinNotifier_LookPathCached(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("FARADAI_ALERT_DESKTOP_ENABLED", "true")

	var lookPathCalls atomic.Int32
	done := make(chan struct{}, 3)
	n := newDarwinNotifier("http://127.0.0.1:19415", settings.NewCache(settings.DefaultOperationalSettings()))
	n.lookPath = func(bin string) (string, error) {
		lookPathCalls.Add(1)
		if bin == "terminal-notifier" {
			return "/opt/homebrew/bin/terminal-notifier", nil
		}
		return "", errors.New("not found")
	}
	n.runner = func(_ context.Context, _ string, _ ...string) error {
		done <- struct{}{}
		return nil
	}

	for i := 0; i < 3; i++ {
		if !n.Notify(AlertEvent{Category: CategoryHITLPending, Title: "HITL", Message: "Cached lookPath", TargetFragment: "audit"}) {
			t.Fatalf("call %d should succeed", i)
		}
	}
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for dispatch #%d", i)
		}
	}

	if got := lookPathCalls.Load(); got != 1 {
		t.Fatalf("expected LookPath to execute once (cached), got %d calls", got)
	}
}
