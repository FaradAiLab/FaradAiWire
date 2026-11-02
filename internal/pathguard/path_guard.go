package pathguard

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Standard permission masks for secure filesystem operations.
const (
	DirPerm    os.FileMode = 0750
	KeyPerm    os.FileMode = 0600
	PolicyPerm os.FileMode = 0644
)

// Security error definitions for path traversal and validation failures.
var (
	ErrPathTraversal     = errors.New("security violation: path traversal attempt detected")
	ErrEmptyPath         = errors.New("security violation: base directory and relative path must not be empty")
	ErrInvalidIdentifier = errors.New("security violation: identifier contains invalid or dangerous characters")
)

var safeIdentifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// ValidateSafeIdentifier verifies that an identifier (such as an agent name, timestamp, or version)
// contains strictly alphanumeric characters, underscores, hyphens, or dots, and does not contain
// directory separators, traversal tokens ('..'), null bytes, or URL-encoded sequences.
func ValidateSafeIdentifier(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%w: identifier cannot be empty", ErrInvalidIdentifier)
	}

	// Reject null bytes, slashes, and traversal components
	if strings.Contains(trimmed, "\x00") ||
		strings.Contains(trimmed, "/") ||
		strings.Contains(trimmed, "\\") ||
		strings.Contains(trimmed, "..") ||
		trimmed == "." {
		return fmt.Errorf("%w: '%s'", ErrInvalidIdentifier, id)
	}

	// If URL encoded (%2e etc), test unescaped value as well
	if strings.Contains(trimmed, "%") {
		unescaped, err := url.QueryUnescape(trimmed)
		if err != nil || strings.Contains(unescaped, "/") || strings.Contains(unescaped, "\\") || strings.Contains(unescaped, "..") {
			return fmt.Errorf("%w: '%s'", ErrInvalidIdentifier, id)
		}
	}

	if !safeIdentifierRegex.MatchString(trimmed) {
		return fmt.Errorf("%w: '%s' does not match safe character pattern", ErrInvalidIdentifier, id)
	}

	return nil
}

// ResolveSandboxedPath verifies that relativePath is strictly confined within baseDir.
// It detects and rejects directory traversal sequences (../, ..\), null byte injections,
// URL-encoded escapes (%2e%2e), and absolute path injections before returning the resolved path.
func ResolveSandboxedPath(baseDir, relativePath string) (string, error) {
	if strings.TrimSpace(baseDir) == "" || strings.TrimSpace(relativePath) == "" {
		return "", ErrEmptyPath
	}

	// 1. Detect null bytes
	if strings.Contains(relativePath, "\x00") || strings.Contains(baseDir, "\x00") {
		return "", ErrPathTraversal
	}

	// 2. Check for URL-encoded traversal payloads (e.g. %2e%2e, %2f, %5c)
	if strings.Contains(relativePath, "%") {
		unescaped, err := url.QueryUnescape(relativePath)
		if err != nil {
			return "", ErrPathTraversal
		}
		if strings.Contains(unescaped, "\x00") ||
			strings.Contains(unescaped, "..") ||
			strings.HasPrefix(unescaped, "/") ||
			strings.HasPrefix(unescaped, "\\") {
			return "", ErrPathTraversal
		}
	}

	// 3. Reject absolute path indicators
	if filepath.IsAbs(relativePath) ||
		strings.HasPrefix(relativePath, "/") ||
		strings.HasPrefix(relativePath, "\\") {
		return "", ErrPathTraversal
	}

	// Reject Windows drive letter indicators (e.g. C:, D:)
	if len(relativePath) >= 2 && relativePath[1] == ':' {
		return "", ErrPathTraversal
	}

	// 4. Normalize path separators and clean relative path
	normalizedRel := strings.ReplaceAll(relativePath, "\\", "/")
	if strings.Contains(normalizedRel, "..") {
		return "", ErrPathTraversal
	}

	cleanRel := filepath.Clean(normalizedRel)
	if cleanRel == ".." ||
		cleanRel == "." ||
		strings.HasPrefix(cleanRel, "../") ||
		strings.HasPrefix(cleanRel, "..\\") {
		return "", ErrPathTraversal
	}

	// Inspect each path segment to ensure no segment is or contains ".."
	parts := strings.Split(cleanRel, "/")
	for _, part := range parts {
		if part == "" || part == "." || strings.Contains(part, "..") {
			return "", ErrPathTraversal
		}
	}

	// 5. Clean base directory and resolve absolute paths
	cleanBase := filepath.Clean(baseDir)
	absBase, err := filepath.Abs(cleanBase)
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute base directory: %w", err)
	}

	fullPath := filepath.Join(cleanBase, cleanRel)
	absFull, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute full path: %w", err)
	}

	// 6. Verify lexical relative containment using filepath.Rel against both relative and absolute representations
	relLexical, err := filepath.Rel(cleanBase, fullPath)
	if err != nil || relLexical == ".." || strings.HasPrefix(relLexical, ".."+string(filepath.Separator)) || strings.HasPrefix(relLexical, "../") {
		return "", ErrPathTraversal
	}

	relAbs, err := filepath.Rel(absBase, absFull)
	if err != nil || relAbs == ".." || strings.HasPrefix(relAbs, ".."+string(filepath.Separator)) || strings.HasPrefix(relAbs, "../") {
		return "", ErrPathTraversal
	}

	// 7. Verify prefix containment on the resulting path
	if absFull != absBase && !strings.HasPrefix(absFull, absBase+string(filepath.Separator)) {
		return "", ErrPathTraversal
	}

	return fullPath, nil
}
