package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpexport"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestExecuteExport_OfflineParityAndNoFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("FARADAI_WIRE_DATA_DIR", filepath.Join(home, ".faradaiwire"))

	dataDir := filepath.Join(home, ".faradaiwire")
	agentsDir := filepath.Join(dataDir, "agents")
	protocolsDir := filepath.Join(dataDir, "protocols")

	repo := agent.NewFSRepository(agentsDir)
	if err := repo.SaveAgentConfig("my-profile", &agent.RouteConfig{
		AgentID:   "my-profile",
		AgentName: "my-profile",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "gh_1",
				Name:         "github",
				Type:         "sse",
				URLOrCommand: "https://api.githubcopilot.com/mcp",
				AuthToken:    "ghp_secret_123",
			},
		},
	}); err != nil {
		t.Fatalf("SaveAgentConfig: %v", err)
	}

	pStore, err := protocol.NewFSStore(protocolsDir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	if err := pStore.Save(&protocol.Protocol{
		ID:            "gh_1",
		Name:          "github",
		Type:          "sse",
		TransportMode: "streamable_http",
		URLOrCommand:  "https://api.githubcopilot.com/mcp",
	}); err != nil {
		t.Fatalf("pStore.Save: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"export", "--profile", "my-profile", "--client", "claude-code", "--scope", "project"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout must be valid JSON: %v\nstdout=%s", err, stdout.String())
	}
	mcpServers := parsed["mcpServers"].(map[string]any)
	gh := mcpServers["github"].(map[string]any)
	if gh["type"] != "http" {
		t.Fatalf("expected protocol.Store TransportMode join -> type=http, got %#v", gh)
	}
	if strings.Contains(stdout.String(), "ghp_secret_123") {
		t.Fatalf("raw secret leaked to stdout")
	}
	if !strings.Contains(stderr.String(), "SECURITY_POLICIES_EXCLUDED") {
		t.Fatalf("expected warnings on stderr, got: %s", stderr.String())
	}

	// Verify silent ./agents fallback is NOT used when active data root lacks the profile.
	wd := t.TempDir()
	localAgents := filepath.Join(wd, "agents", "cwd-only", "current")
	if err := os.MkdirAll(localAgents, 0750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(localAgents, "config.json"), []byte(`{"agent_id":"cwd-only","protocols":[]}`), 0600)
	origWD, _ := os.Getwd()
	_ = os.Chdir(wd)
	defer func() { _ = os.Chdir(origWD) }()

	var out2, err2 bytes.Buffer
	if code := runCLI([]string{"export", "--profile", "cwd-only", "--client", "generic"}, nil, &out2, &err2); code == 0 {
		t.Fatalf("expected non-zero exit when profile is missing from active data root, got 0")
	}
}

func TestExecuteExport_RejectsPlaintextRemoteAndProtectsClientFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("FARADAI_WIRE_DATA_DIR", filepath.Join(home, ".faradaiwire"))

	dataDir := filepath.Join(home, ".faradaiwire")
	repo := agent.NewFSRepository(filepath.Join(dataDir, "agents"))
	if err := repo.SaveAgentConfig("p1", &agent.RouteConfig{
		AgentID:   "p1",
		AgentName: "p1",
		Protocols: []agent.ProtocolConfig{{ID: "fs", Name: "fs", Type: "stdio", Command: "npx", Args: []string{"-y", "fs"}}},
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Remote non-loopback http:// must be rejected before dialing.
	var out, errBuf bytes.Buffer
	code := runCLI([]string{"export", "--profile", "p1", "--client", "generic", "--admin-url", "http://gateway.example.com:19415"}, nil, &out, &errBuf)
	if code == 0 || !strings.Contains(errBuf.String(), "https://") {
		t.Fatalf("expected rejection of plaintext non-loopback http://, got code=%d stderr=%s", code, errBuf.String())
	}

	// 2. Protected client path via symlinked ancestor + case-variant on darwin/windows.
	realCursorDir := filepath.Join(home, "real-cursor")
	if err := os.MkdirAll(realCursorDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realCursorDir, filepath.Join(home, ".cursor")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".cursor", "mcp.json")
	if err := writeNewExportFile(target, []byte("{}"), runtime.GOOS); err == nil {
		t.Fatalf("expected symlinked ~/.cursor/mcp.json to be refused")
	}
	if err := writeNewExportFile(filepath.Join(home, ".Cursor", "mcp.json"), []byte("{}"), "darwin"); err == nil {
		t.Fatalf("expected case-variant ~/.Cursor/mcp.json on darwin to be refused")
	}
	if err := writeNewExportFile(filepath.Join(home, "proj", ".mcp.json"), []byte("{}"), runtime.GOOS); err == nil {
		t.Fatalf("expected workspace /.mcp.json suffix to be refused")
	}

	// 3. Brand-new safe path succeeds with 0600 and refuses subsequent overwrite.
	safeOut := filepath.Join(home, "exports", "p1-cursor.json")
	out.Reset()
	errBuf.Reset()
	if code := runCLI([]string{"export", "--profile", "p1", "--client", "cursor", "--out", safeOut}, nil, &out, &errBuf); code != 0 {
		t.Fatalf("expected safe --out to succeed, got code=%d stderr=%s", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout when --out is set, got %s", out.String())
	}
	fi, err := os.Stat(safeOut)
	if err != nil {
		t.Fatalf("stat safeOut: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm, got %o", fi.Mode().Perm())
	}
	if code := runCLI([]string{"export", "--profile", "p1", "--client", "cursor", "--out", safeOut}, nil, &out, &errBuf); code == 0 {
		t.Fatalf("expected second write to existing --out file to fail")
	}
}

func TestExecuteExport_RemoteAdminCompanionAndRedirects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("FARADAI_WIRE_DATA_DIR", filepath.Join(home, ".faradaiwire"))
	t.Setenv("ADMIN_API_KEY", "test-admin-secret-key")

	var gotAuth string
	var gotPath string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcpexport.ExportResult{
			Client:         mcpexport.ClientClaudeCode,
			Scope:          mcpexport.ScopeProject,
			TargetPathHint: ".mcp.json",
			Config:         map[string]any{"mcpServers": map[string]any{"gh": map[string]any{"type": "http", "url": "https://mcp.example.com"}}},
			CompanionFiles: []mcpexport.CompanionFile{
				{
					PathHint:    ".claude/settings.json",
					MergeHazard: true,
					Content:     map[string]any{"permissions": map[string]any{"deny": []string{"mcp__gh__delete_repo"}}},
				},
			},
			Warnings: []mcpexport.Warning{},
		})
	}))
	defer apiSrv.Close()

	primaryOut := filepath.Join(home, "exports", "primary.mcp.json")
	companionOut := filepath.Join(home, "exports", "companion.settings.json")
	var out, errBuf bytes.Buffer
	code := runCLI([]string{
		"export",
		"--profile", "remote-prof",
		"--client", "claude-code",
		"--scope", "project",
		"--admin-url", apiSrv.URL,
		"--out", primaryOut,
		"--companion-out", companionOut,
	}, nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("remote export failed: code=%d stderr=%s", code, errBuf.String())
	}
	if gotAuth != "Bearer test-admin-secret-key" {
		t.Fatalf("Authorization = %q, want Bearer test-admin-secret-key", gotAuth)
	}
	if gotPath != "/admin/agents/remote-prof/export" {
		t.Fatalf("path = %q", gotPath)
	}
	if _, err := os.Stat(companionOut); err != nil {
		t.Fatalf("expected companion output written: %v", err)
	}

	// Verify HTTP redirects are blocked.
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.example.com/steal", http.StatusFound)
	}))
	defer redirSrv.Close()

	out.Reset()
	errBuf.Reset()
	if code := runCLI([]string{"export", "--profile", "remote-prof", "--client", "generic", "--admin-url", redirSrv.URL}, nil, &out, &errBuf); code == 0 {
		t.Fatalf("expected HTTP redirect to be rejected")
	}

	// Verify protected companion path is rejected.
	out.Reset()
	errBuf.Reset()
	protectedComp := filepath.Join(home, "proj", ".claude", "settings.json")
	if code := runCLI([]string{
		"export",
		"--profile", "remote-prof",
		"--client", "claude-code",
		"--admin-url", apiSrv.URL,
		"--out", filepath.Join(home, "exports", "p2.json"),
		"--companion-out", protectedComp,
	}, nil, &out, &errBuf); code == 0 {
		t.Fatalf("expected protected companion-out path %q to be refused", protectedComp)
	}
}
