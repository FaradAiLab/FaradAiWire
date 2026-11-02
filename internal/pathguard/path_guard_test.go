package pathguard

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestPathGuard_ResolveSandboxedPath(t *testing.T) {
	tempBase := t.TempDir()

	tests := []struct {
		name        string
		baseDir     string
		relPath     string
		expectError bool
		errTarget   error
	}{
		// Valid cases
		{
			name:        "Simple valid file in base directory",
			baseDir:     tempBase,
			relPath:     "policy.json",
			expectError: false,
		},
		{
			name:        "Nested subdirectory path",
			baseDir:     tempBase,
			relPath:     "agents/agent-1/config.json",
			expectError: false,
		},
		{
			name:        "Deep nested valid path",
			baseDir:     tempBase,
			relPath:     "a/b/c/d/e.txt",
			expectError: false,
		},
		{
			name:        "Relative path with safe internal dot",
			baseDir:     tempBase,
			relPath:     "policies/./custom.json",
			expectError: false,
		},

		// Empty paths
		{
			name:        "Empty baseDir rejected",
			baseDir:     "",
			relPath:     "policy.json",
			expectError: true,
			errTarget:   ErrEmptyPath,
		},
		{
			name:        "Whitespace baseDir rejected",
			baseDir:     "   ",
			relPath:     "policy.json",
			expectError: true,
			errTarget:   ErrEmptyPath,
		},
		{
			name:        "Empty relPath rejected",
			baseDir:     tempBase,
			relPath:     "",
			expectError: true,
			errTarget:   ErrEmptyPath,
		},
		{
			name:        "Whitespace relPath rejected",
			baseDir:     tempBase,
			relPath:     "   ",
			expectError: true,
			errTarget:   ErrEmptyPath,
		},

		// Standard directory traversal sequences
		{
			name:        "Single parent directory traversal",
			baseDir:     tempBase,
			relPath:     "../etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Double dot only",
			baseDir:     tempBase,
			relPath:     "..",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Multiple parent directory traversal",
			baseDir:     tempBase,
			relPath:     "../../../../etc/shadow",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Internal traversal escaping root",
			baseDir:     tempBase,
			relPath:     "agents/agent-1/../../../../etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Traversal using backslashes",
			baseDir:     tempBase,
			relPath:     "..\\..\\etc\\passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Nested repeated dots sequence (....//....//)",
			baseDir:     tempBase,
			relPath:     "....//....//etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},

		// Absolute path indicators
		{
			name:        "Unix absolute path",
			baseDir:     tempBase,
			relPath:     "/etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Windows root path",
			baseDir:     tempBase,
			relPath:     "\\Windows\\System32",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Windows drive letter path",
			baseDir:     tempBase,
			relPath:     "C:\\Windows\\System32\\cmd.exe",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},

		// Null-byte injection
		{
			name:        "Null byte in relative path",
			baseDir:     tempBase,
			relPath:     "policy.json\x00/../../etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "Null byte in base directory",
			baseDir:     tempBase + "\x00/sub",
			relPath:     "policy.json",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},

		// URL encoded traversal sequences
		{
			name:        "URL-encoded %2e%2e/ sequence",
			baseDir:     tempBase,
			relPath:     "%2e%2e/etc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "URL-encoded %2e%2e%2f sequence",
			baseDir:     tempBase,
			relPath:     "%2e%2e%2f%2e%2e%2fetc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "URL-encoded null byte %00",
			baseDir:     tempBase,
			relPath:     "policy.json%00.txt",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
		{
			name:        "URL-encoded backslash %5c",
			baseDir:     tempBase,
			relPath:     "..%5c..%5cetc/passwd",
			expectError: true,
			errTarget:   ErrPathTraversal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := ResolveSandboxedPath(tc.baseDir, tc.relPath)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for relPath %q, but got success with resolved path %q", tc.relPath, resolved)
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Fatalf("expected error wrapping %v, got %v", tc.errTarget, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for relPath %q: %v", tc.relPath, err)
				}
				expectedPath := filepath.Join(filepath.Clean(tc.baseDir), filepath.Clean(tc.relPath))
				if resolved != expectedPath {
					t.Fatalf("expected resolved path %q, got %q", expectedPath, resolved)
				}
			}
		})
	}
}

func TestPathGuard_ValidateSafeIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		// Valid identifiers
		{name: "Simple alphanumeric", id: "agent1", expectError: false},
		{name: "Identifier with hyphens and underscores", id: "agent_qa-01", expectError: false},
		{name: "Timestamp identifier", id: "20260824_153000", expectError: false},
		{name: "Dotted timestamp identifier", id: "2026.08.24-12.00.00", expectError: false},

		// Malicious or invalid identifiers
		{name: "Empty identifier", id: "", expectError: true},
		{name: "Whitespace only", id: "   ", expectError: true},
		{name: "Parent directory traversal", id: "../", expectError: true},
		{name: "Double dot", id: "..", expectError: true},
		{name: "Single dot", id: ".", expectError: true},
		{name: "Embedded slash", id: "agent/sub", expectError: true},
		{name: "Embedded backslash", id: "agent\\sub", expectError: true},
		{name: "URL-encoded traversal (%2e%2e)", id: "%2e%2e", expectError: true},
		{name: "Null byte injection", id: "agent\x00_test", expectError: true},
		{name: "Spaces inside", id: "agent test", expectError: true},
		{name: "Special characters ($@;)", id: "agent$1", expectError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSafeIdentifier(tc.id)
			if tc.expectError && err == nil {
				t.Fatalf("expected error for identifier %q, got nil", tc.id)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error for identifier %q: %v", tc.id, err)
			}
		})
	}
}
