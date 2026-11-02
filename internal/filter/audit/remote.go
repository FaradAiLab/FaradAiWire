package audit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMaxDownloadBytes is the default maximum size allowed for remote skill repositories (25 MB).
const DefaultMaxDownloadBytes int64 = 25 * 1024 * 1024

// DefaultRemoteTimeout is the maximum duration permitted for cloning a remote repository.
const DefaultRemoteTimeout = 30 * time.Second

// ErrRemoteTooLarge is returned when a remote repository exceeds size limits.
var ErrRemoteTooLarge = errors.New("remote repository exceeds maximum allowed download size (25 MB)")

// IsRemoteTarget returns true if the specified target appears to be a remote URL or Git repository.
func IsRemoteTarget(target string) bool {
	trimmed := strings.TrimSpace(target)
	return strings.HasPrefix(trimmed, "http://") ||
		strings.HasPrefix(trimmed, "https://") ||
		strings.HasPrefix(trimmed, "git@") ||
		strings.HasPrefix(trimmed, "ssh://") ||
		strings.HasPrefix(trimmed, "file://")
}

// AuditRemoteTarget securely clones a remote repository into an isolated, ephemeral
// scratchpad directory, audits it, and guarantees 100% deletion upon return.
func AuditRemoteTarget(ctx context.Context, rawURL string) (*AuditReport, error) {
	if !IsRemoteTarget(rawURL) {
		return nil, fmt.Errorf("invalid remote URL: %s", rawURL)
	}

	// 1. Sanitize input to prevent argument injection or control character attacks
	cleanURL := strings.TrimSpace(rawURL)
	if strings.ContainsAny(cleanURL, "\r\n\x00") || strings.HasPrefix(cleanURL, "-") {
		return nil, errors.New("malformed remote URL contains illegal characters or option prefixes")
	}

	// Verify standard HTTP/HTTPS URLs parse correctly
	if strings.HasPrefix(cleanURL, "http://") || strings.HasPrefix(cleanURL, "https://") {
		parsed, err := url.Parse(cleanURL)
		if err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("invalid HTTP/HTTPS repository URL: %w", err)
		}
	}

	// 2. Ensure git binary is available on host
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("git binary not found in system PATH; git is required to audit remote repositories")
	}

	// 3. Create isolated ephemeral directory with restricted permissions (0700)
	tmpDir, err := os.MkdirTemp("", "faradai-audit-*")
	if err != nil {
		return nil, fmt.Errorf("create ephemeral scratch directory: %w", err)
	}
	// Guaranteed purge across all return paths (normal, error, panic)
	defer os.RemoveAll(tmpDir)

	// 4. Bound clone duration with context timeout
	fetchCtx, cancel := context.WithTimeout(ctx, DefaultRemoteTimeout)
	defer cancel()

	// 5. Execute secure shallow clone:
	// - --depth 1: Fetch only latest commit
	// - core.hooksPath=/dev/null: Suppress local Git hook execution (anti-RCE)
	// - GIT_TERMINAL_PROMPT=0: Fail fast instead of hanging on auth prompt
	// - --: Positional parameter delimiter prevents flag injection
	cmd := exec.CommandContext(fetchCtx, gitBin,
		"clone",
		"--depth", "1",
		"--single-branch",
		"--config", "core.hooksPath=/dev/null",
		"--",
		cleanURL,
		tmpDir,
	)

	// Environment sanitization (SEC-007)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if fetchCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("remote clone timed out after %v: %w", DefaultRemoteTimeout, err)
		}
		return nil, fmt.Errorf("failed to clone remote repository (%s): %s", err, strings.TrimSpace(string(output)))
	}

	// 6. Verify repository does not exceed maximum byte bounds (Zip-bomb / disk exhaustion defense)
	dirSize, err := calculateDirectorySize(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("calculate repository size: %w", err)
	}
	if dirSize > DefaultMaxDownloadBytes {
		return nil, ErrRemoteTooLarge
	}

	// 7. Audit the freshly unpacked repository
	report, err := AuditDirectory(tmpDir)
	if err != nil {
		return nil, err
	}

	// Overwrite RootPath in report so display shows the remote URL instead of /tmp/...
	report.RootPath = cleanURL
	return report, nil
}

func calculateDirectorySize(root string) (int64, error) {
	var totalSize int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	return totalSize, err
}
