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
