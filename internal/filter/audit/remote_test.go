package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsRemoteTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"https://github.com/FaradAiLab/FaradAiWire", true},
		{"http://gitlab.local/agent-skills/repo.git", true},
		{"git@github.com:FaradAiLab/FaradAiWire.git", true},
		{"ssh://git@custom.host/repo", true},
		{"./skills/git-helper", false},
		{"/var/skills/scanner", false},
		{"relative/path/to/skill", false},
		{"", false},
	}

	for _, tc := range tests {
		got := IsRemoteTarget(tc.input)
		if got != tc.expected {
			t.Errorf("IsRemoteTarget(%q) = %v; expected %v", tc.input, got, tc.expected)
		}
	}
}

func TestAuditRemoteTarget_Sanitization(t *testing.T) {
	ctx := context.Background()

	// 1. Argument injection attempt
	_, err := AuditRemoteTarget(ctx, "--upload-pack=calc.exe")
	if err == nil {
		t.Errorf("expected error for flag-prefixed URL, got nil")
	}

	// 2. Control characters / newlines
	_, err = AuditRemoteTarget(ctx, "https://github.com/evil/repo\nrm -rf /")
	if err == nil {
		t.Errorf("expected error for URL with newline, got nil")
	}

	// 3. Local path passed to remote auditor
	_, err = AuditRemoteTarget(ctx, "./local/path")
	if err == nil {
		t.Errorf("expected error for local path, got nil")
	}
}

func TestAuditRemoteTarget_EphemeralLifecycle(t *testing.T) {
	// Verify git binary is installed
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed, skipping test")
	}

	// Create a local git repository to act as the "remote" repository
	originDir := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = originDir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@test.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git command %v failed: %s", args, string(out))
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test User")

	cleanFile := filepath.Join(originDir, "SKILL.md")
	if err := os.WriteFile(cleanFile, []byte("# Remote Skill\nClean remote skill."), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "SKILL.md")
	runGit("commit", "-m", "Initial commit")

	// Use file:// origin URL as remote target
	fileURL := "file://" + originDir
	ctx := context.Background()

	report, err := AuditRemoteTarget(ctx, fileURL)
	if err != nil {
		t.Fatalf("AuditRemoteTarget failed: %v", err)
	}

	if report.ScannedFilesCount != 1 {
		t.Errorf("expected 1 scanned file, got %d", report.ScannedFilesCount)
	}

	if len(report.Issues) != 0 {
		t.Errorf("expected clean remote report, got %d issues", len(report.Issues))
	}

	if report.RootPath != fileURL {
		t.Errorf("expected RootPath to be %s, got %s", fileURL, report.RootPath)
	}

	// Verify ephemeral directory was deleted
	// By checking that no lingering faradai-audit-* dirs with our file exist
	pattern := filepath.Join(os.TempDir(), "faradai-audit-*")
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		if _, err := os.Stat(filepath.Join(m, "SKILL.md")); err == nil {
			t.Errorf("scratch directory %s was not cleaned up!", m)
		}
	}
}
