//go:build darwin

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

const (
	defaultNotifyMaxConcurrent = 4
	defaultDispatchTimeout     = 3 * time.Second
	notifierBundleID           = "com.faradailab.faradaiwire.notifier"
	notifierAppName            = "FaradAiWire"
	notifierAppletVersion      = "1"

	osascriptDisplayNotification = `on run argv
	display notification (item 1 of argv) with title (item 2 of argv)
end run`

	notifierAppletSource = `on run
	set homePosix to POSIX path of (path to home folder)
	set baseDir to homePosix & ".faradaiwire/notifier/"
	set pendingFile to POSIX file (baseDir & "pending_alert.txt")
	set pendingText to ""
	try
		set pendingText to (read pendingFile as «class utf8»)
	end try
	if pendingText is not "" then
		try
			set fp to open for access pendingFile with write permission
			set eof of fp to 0
			close access fp
		on error
			try
				close access pendingFile
			end try
		end try
		set linesList to paragraphs of pendingText
		if (count of linesList) >= 2 then
			set alertTitle to item 1 of linesList
			set alertMsg to item 2 of linesList
			if alertTitle is not "" and alertMsg is not "" then
				display notification alertMsg with title alertTitle sound name "Ping"
				return
			end if
		end if
	end if
	my openSavedAlertURL(baseDir)
end run

on reopen
	set homePosix to POSIX path of (path to home folder)
	set baseDir to homePosix & ".faradaiwire/notifier/"
	my openSavedAlertURL(baseDir)
end reopen

on openSavedAlertURL(baseDir)
	set urlFile to POSIX file (baseDir & "last_alert_url.txt")
	set targetURL to ""
	try
		set targetURL to (read urlFile as «class utf8»)
	end try
	if targetURL is not "" then
		set targetURL to item 1 of (paragraphs of targetURL)
		if targetURL starts with "http://" or targetURL starts with "https://" then
			open location targetURL
		end if
	end if
end openSavedAlertURL`
)

type darwinNotifier struct {
	mu            sync.RWMutex
	adminBaseURL  string
	settingsCache *settings.Cache
	cooldowns     *cooldownTracker
	sem           chan struct{}

	helperOnce sync.Once
	helperMu   sync.Mutex
	helperPath string
	helperErr  error

	runner   func(ctx context.Context, name string, args ...string) error
	lookPath func(string) (string, error)
	homeDir  func() (string, error)
}

var defaultDarwinNotifier = newDarwinNotifier("", nil)

func newPlatformNotifier(adminBaseURL string, settingsCache *settings.Cache) DesktopNotifier {
	return newDarwinNotifier(adminBaseURL, settingsCache)
}

func newDarwinNotifier(adminBaseURL string, settingsCache *settings.Cache) *darwinNotifier {
	return &darwinNotifier{
		adminBaseURL:  strings.TrimRight(strings.TrimSpace(adminBaseURL), "/"),
		settingsCache: settingsCache,
		cooldowns:     newCooldownTracker(nil),
		sem:           make(chan struct{}, defaultNotifyMaxConcurrent),
	}
}

// NotifyDefault triggers a platform desktop notification using package defaults.
func NotifyDefault(event AlertEvent) bool {
	return defaultDarwinNotifier.Notify(event)
}

// ResetCooldowns clears package-default notification cooldown timers.
func ResetCooldowns() {
	defaultDarwinNotifier.cooldowns.Reset()
}

func (n *darwinNotifier) SetAdminBaseURL(baseURL string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.adminBaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

func (n *darwinNotifier) AdminBaseURL() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.adminBaseURL
}

func (n *darwinNotifier) Notify(event AlertEvent) bool {
	if !isCategoryEnabled(event.Category, n.settingsCache) {
		return false
	}

	title := sanitizeSingleLine(event.Title)
	msg := sanitizeSingleLine(event.Message)
	if title == "" {
		title = notifierAppName
	}
	if msg == "" {
		return false
	}

	cooldown := resolveCategoryCooldown(event.Category, n.settingsCache)
	if !n.cooldowns.Allow(event.Category, cooldown) {
		return false
	}

	// Never spawn OS notification subprocesses or mutate ~/.faradaiwire during `go test`
	// unless an explicit mock runner is injected.
	if n.runner == nil && testing.Testing() {
		return true
	}

	frag := event.TargetFragment
	if frag == "" {
		frag = DefaultFragmentForCategory(event.Category)
	}
	targetURL := BuildDashboardURLFromBase(n.AdminBaseURL(), frag)

	select {
	case n.sem <- struct{}{}:
	default:
		return false
	}

	go func() {
		defer func() { <-n.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), defaultDispatchTimeout)
		defer cancel()
		n.dispatch(ctx, event.Category, title, msg, targetURL)
	}()

	return true
}

func (n *darwinNotifier) dispatch(ctx context.Context, cat AlertCategory, title, msg, targetURL string) {
	if n.dispatchTier1(ctx, cat, title, msg, targetURL) {
		return
	}
	if n.dispatchTier2(ctx, title, msg, targetURL) {
		return
	}
	if err := n.dispatchTier3(ctx, title, msg); err != nil {
		slog.Debug("desktop alert dispatch failed across all tiers",
			slog.String("category", string(cat)),
			slog.String("error", err.Error()),
		)
	}
}

func (n *darwinNotifier) dispatchTier1(ctx context.Context, cat AlertCategory, title, msg, targetURL string) bool {
	bin, err := n.findPath("terminal-notifier")
	if err != nil || bin == "" {
		return false
	}

	group := "faradaiwire-alert"
	if cat != "" {
		group = "faradaiwire-" + string(cat)
	}

	args := []string{
		"-title", escapeTerminalNotifierArg(title),
		"-message", escapeTerminalNotifierArg(msg),
		"-group", group,
		"-sound", "Ping",
	}
	if ValidateHTTPURL(targetURL) {
		args = append(args, "-open", targetURL)
	}

	if err := n.runCmd(ctx, bin, args...); err != nil {
		slog.Debug("terminal-notifier dispatch failed, falling back to helper app",
			slog.String("error", err.Error()),
		)
		return false
	}
	return true
}

func (n *darwinNotifier) dispatchTier2(ctx context.Context, title, msg, targetURL string) bool {
	baseDir, appPath, err := n.ensureHelperApp(ctx)
	if err != nil {
		slog.Debug("macOS helper app preparation failed, falling back to osascript",
			slog.String("error", err.Error()),
		)
		return false
	}

	n.helperMu.Lock()
	defer n.helperMu.Unlock()

	urlPayload := ""
	if ValidateHTTPURL(targetURL) {
		urlPayload = targetURL + "\n"
	}
	if err := atomicWriteFile(filepath.Join(baseDir, "last_alert_url.txt"), []byte(urlPayload), 0o600); err != nil {
		slog.Debug("failed writing desktop alert URL state", slog.String("error", err.Error()))
		return false
	}

	pendingPayload := title + "\n" + msg + "\n"
	if err := atomicWriteFile(filepath.Join(baseDir, "pending_alert.txt"), []byte(pendingPayload), 0o600); err != nil {
		slog.Debug("failed writing pending desktop alert payload", slog.String("error", err.Error()))
		return false
	}

	if err := n.runCmd(ctx, "/usr/bin/open", "-W", "-g", "-a", appPath); err != nil {
		slog.Debug("failed launching desktop alert helper app", slog.String("error", err.Error()))
		return false
	}
	return true
}

func (n *darwinNotifier) dispatchTier3(ctx context.Context, title, msg string) error {
	return n.runCmd(ctx, "/usr/bin/osascript", "-e", osascriptDisplayNotification, msg, title)
}

func (n *darwinNotifier) ensureHelperApp(ctx context.Context) (string, string, error) {
	home, err := n.resolveHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("resolve home dir: %w", err)
	}
	baseDir := filepath.Join(home, ".faradaiwire", "notifier")

	n.helperOnce.Do(func() {
		if err := os.MkdirAll(baseDir, 0o700); err != nil {
			n.helperErr = fmt.Errorf("create notifier dir: %w", err)
			return
		}

		appPath := filepath.Join(baseDir, "FaradAiWireNotifier.app")
		versionFile := filepath.Join(baseDir, ".applet-version")
		if isHelperAppCurrent(appPath, versionFile) {
			n.helperPath = appPath
			return
		}

		if err := n.buildHelperApp(ctx, baseDir, appPath, versionFile); err != nil {
			n.helperErr = err
			return
		}
		n.helperPath = appPath
	})

	if n.helperErr != nil {
		return "", "", n.helperErr
	}
	return baseDir, n.helperPath, nil
}

func (n *darwinNotifier) buildHelperApp(ctx context.Context, baseDir, appPath, versionFile string) error {
	srcFile, err := os.CreateTemp(baseDir, "notifier-*.applescript")
	if err != nil {
		return fmt.Errorf("create temporary script: %w", err)
	}
	srcPath := srcFile.Name()
	defer func() { _ = os.Remove(srcPath) }()

	if _, err := srcFile.WriteString(notifierAppletSource); err != nil {
		_ = srcFile.Close()
		return fmt.Errorf("write temporary script: %w", err)
	}
	if err := srcFile.Close(); err != nil {
		return fmt.Errorf("close temporary script: %w", err)
	}

	stagingApp := filepath.Join(baseDir, "FaradAiWireNotifier.app.tmp")
	_ = os.RemoveAll(stagingApp)
	defer func() { _ = os.RemoveAll(stagingApp) }()

	if err := n.runCmd(ctx, "/usr/bin/osacompile", "-o", stagingApp, srcPath); err != nil {
		return fmt.Errorf("osacompile helper app: %w", err)
	}

	plistPath := filepath.Join(stagingApp, "Contents", "Info.plist")
	plistEdits := [][]string{
		{"-replace", "CFBundleIdentifier", "-string", notifierBundleID, plistPath},
		{"-replace", "CFBundleName", "-string", notifierAppName, plistPath},
		{"-replace", "CFBundleShortVersionString", "-string", notifierAppletVersion, plistPath},
		{"-replace", "LSUIElement", "-bool", "true", plistPath},
	}
	for _, editArgs := range plistEdits {
		if err := n.runCmd(ctx, "/usr/bin/plutil", editArgs...); err != nil {
			return fmt.Errorf("plutil %s: %w", editArgs[1], err)
		}
	}

	if err := n.runCmd(ctx, "/usr/bin/codesign", "--force", "--deep", "--sign", "-", stagingApp); err != nil {
		return fmt.Errorf("codesign helper app: %w", err)
	}

	if err := swapAppBundle(stagingApp, appPath); err != nil {
		return fmt.Errorf("install helper app: %w", err)
	}

	if err := atomicWriteFile(versionFile, []byte(notifierAppletVersion+"\n"), 0o600); err != nil {
		return fmt.Errorf("write applet version stamp: %w", err)
	}
	return nil
}

func isHelperAppCurrent(appPath, versionFile string) bool {
	verBytes, err := os.ReadFile(versionFile)
	if err != nil || strings.TrimSpace(string(verBytes)) != notifierAppletVersion {
		return false
	}
	if _, err := os.Stat(filepath.Join(appPath, "Contents", "MacOS", "applet")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(appPath, "Contents", "Info.plist")); err != nil {
		return false
	}
	return true
}

func swapAppBundle(stagingApp, targetApp string) error {
	backupApp := targetApp + ".bak"
	_ = os.RemoveAll(backupApp)

	hadExisting := false
	if _, err := os.Stat(targetApp); err == nil {
		hadExisting = true
		if err := os.Rename(targetApp, backupApp); err != nil {
			return err
		}
	}

	if err := os.Rename(stagingApp, targetApp); err != nil {
		if hadExisting {
			_ = os.Rename(backupApp, targetApp)
		}
		return err
	}

	if hadExisting {
		_ = os.RemoveAll(backupApp)
	}
	return nil
}

func (n *darwinNotifier) runCmd(ctx context.Context, name string, args ...string) error {
	if n.runner != nil {
		return n.runner(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).Run()
}

func (n *darwinNotifier) findPath(bin string) (string, error) {
	if n.lookPath != nil {
		return n.lookPath(bin)
	}
	return exec.LookPath(bin)
}

func (n *darwinNotifier) resolveHomeDir() (string, error) {
	if n.homeDir != nil {
		return n.homeDir()
	}
	return os.UserHomeDir()
}

func escapeTerminalNotifierArg(s string) string {
	if strings.HasPrefix(s, "[") || strings.HasPrefix(s, "-") {
		return `\` + s
	}
	return s
}

func sanitizeSingleLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
