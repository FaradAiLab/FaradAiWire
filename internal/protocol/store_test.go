package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProtocolValidation(t *testing.T) {
	tests := []struct {
		name    string
		proto   *Protocol
		wantErr bool
	}{
		{
			name: "Valid Stdio Protocol",
			proto: &Protocol{
				ID:      "github",
				Name:    "GitHub",
				Type:    "stdio",
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-github"},
			},
			wantErr: false,
		},
		{
			name: "Valid SSE Protocol",
			proto: &Protocol{
				ID:           "context7",
				Name:         "Context7",
				Type:         "sse",
				URLOrCommand: "https://mcp.context7.com/mcp",
			},
			wantErr: false,
		},
		{
			name: "Invalid ID with path traversal",
			proto: &Protocol{
				ID:           "../hack",
				Name:         "Hacked",
				Type:         "sse",
				URLOrCommand: "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "Invalid ID with slash",
			proto: &Protocol{
				ID:           "folder/hack",
				Name:         "Hacked",
				Type:         "sse",
				URLOrCommand: "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "Missing Target Command and URL",
			proto: &Protocol{
				ID:   "empty",
				Type: "stdio",
			},
			wantErr: true,
		},
		{
			name: "Invalid Type",
			proto: &Protocol{
				ID:           "weird",
				Type:         "ftp",
				URLOrCommand: "ftp://example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.proto.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestProtocolMaskSecrets(t *testing.T) {
	p := &Protocol{
		ID:           "github",
		Name:         "GitHub",
		Type:         "stdio",
		URLOrCommand: "http://user:secretpass@localhost:8080/sse",
		Env: []string{
			"GITHUB_TOKEN=ghp_1234567890abcdef",
			"DEBUG=true",
			"API_KEY=short",
			"CUSTOM_PATH=${MY_PATH}",
		},
	}

	masked := p.MaskSecrets()
	if masked == nil {
		t.Fatal("MaskSecrets() returned nil")
	}

	// URL basic auth redacted
	if strings.Contains(masked.URLOrCommand, "secretpass") {
		t.Fatalf("URL was not redacted: %s", masked.URLOrCommand)
	}

	for _, env := range masked.Env {
		if strings.HasPrefix(env, "GITHUB_TOKEN=") {
			if strings.Contains(env, "1234567890") {
				t.Fatalf("Secret token was not masked: %s", env)
			}
			if !strings.Contains(env, "••••••") {
				t.Fatalf("Expected mask dots in token, got: %s", env)
			}
		}
		if strings.HasPrefix(env, "DEBUG=") {
			if env != "DEBUG=true" {
				t.Fatalf("Non-sensitive variable should not be masked: %s", env)
			}
		}
		if strings.HasPrefix(env, "CUSTOM_PATH=") {
			if env != "CUSTOM_PATH=${MY_PATH}" {
				t.Fatalf("Variable reference should not be masked: %s", env)
			}
		}
	}
}

func TestPresetsIncludeTop20AndContext7(t *testing.T) {
	presets := GetPresets()
	if len(presets) < 20 {
		t.Fatalf("Expected at least 20 presets, got %d", len(presets))
	}

	var foundContext7, foundGitHub, foundPostgres bool
	for _, pr := range presets {
		if pr.ID == "context7" {
			foundContext7 = true
			if pr.Type != "http" || pr.URL != "https://mcp.context7.com/mcp" {
				t.Fatalf("Invalid Context7 preset configuration: %+v", pr)
			}
		}
		if pr.ID == "github" {
			foundGitHub = true
		}
		if pr.ID == "postgres" {
			foundPostgres = true
		}
	}

	if !foundContext7 {
		t.Fatal("Context7 preset was not found in presets list")
	}
	if !foundGitHub {
		t.Fatal("GitHub preset was not found in presets list")
	}
	if !foundPostgres {
		t.Fatal("Postgres preset was not found in presets list")
	}
}

func TestFSStoreCRUDAndPermissions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "faradai_proto_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFSStore(tempDir)
	if err != nil {
		t.Fatalf("NewFSStore failed: %v", err)
	}

	proto := &Protocol{
		ID:           "test-postgres",
		Name:         "Test Postgres DB",
		Type:         "stdio",
		Command:      "npx",
		Args:         []string{"-y", "@modelcontextprotocol/server-postgres"},
		Env:          []string{"POSTGRES_URL=postgresql://localhost/db"},
		AllowedTools: []string{"query", "list_tables"},
	}

	// 1. Save
	if err := store.Save(proto); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 2. Verify file permissions are 0600
	savedPath := filepath.Join(tempDir, "test-postgres.json")
	info, statErr := os.Stat(savedPath)
	if statErr != nil {
		t.Fatalf("Stat failed on saved file: %v", statErr)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("Expected file permissions 0600, got %o", perm)
	}

	// 3. Get
	fetched, getErr := store.Get("test-postgres")
	if getErr != nil {
		t.Fatalf("Get failed: %v", getErr)
	}
	if fetched.ID != proto.ID || fetched.Name != proto.Name || len(fetched.AllowedTools) != 2 {
		t.Fatalf("Fetched protocol mismatch: %+v", fetched)
	}

	// 4. List
	list, listErr := store.List()
	if listErr != nil {
		t.Fatalf("List failed: %v", listErr)
	}
	if len(list) != 1 || list[0].ID != "test-postgres" {
		t.Fatalf("Expected 1 protocol in list, got %d", len(list))
	}

	// 5. Referential Integrity Check
	store.SetAgentUsageChecker(func(id string) ([]string, error) {
		if id == "test-postgres" {
			return []string{"agent-alpha", "agent-beta"}, nil
		}
		return nil, nil
	})

	delErr := store.Delete("test-postgres")
	if delErr == nil || !strings.Contains(delErr.Error(), "in use by one or more agents") {
		t.Fatalf("Expected ErrProtocolInUse, got: %v", delErr)
	}

	// 6. Free up reference and delete
	store.SetAgentUsageChecker(func(id string) ([]string, error) {
		return nil, nil
	})

	if err := store.Delete("test-postgres"); err != nil {
		t.Fatalf("Delete failed after clearing reference: %v", err)
	}

	// 7. Verify deletion
	_, notFoundErr := store.Get("test-postgres")
	if notFoundErr != ErrProtocolNotFound {
		t.Fatalf("Expected ErrProtocolNotFound, got: %v", notFoundErr)
	}
}

func TestFSStoreConcurrentAccess(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "faradai_proto_concurrent_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFSStore(tempDir)
	if err != nil {
		t.Fatalf("NewFSStore failed: %v", err)
	}

	var wg sync.WaitGroup
	numRoutines := 20

	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		id := string(rune('a' + i))
		go func(protoID string) {
			defer wg.Done()
			p := &Protocol{
				ID:           "proto-" + protoID,
				Type:         "sse",
				URLOrCommand: "http://localhost:8080/sse",
			}
			_ = store.Save(p)
			_, _ = store.Get("proto-" + protoID)
			_, _ = store.List()
		}(id)
	}

	wg.Wait()

	list, err := store.List()
	if err != nil {
		t.Fatalf("List after concurrency failed: %v", err)
	}
	if len(list) != numRoutines {
		t.Fatalf("Expected %d protocols, got %d", numRoutines, len(list))
	}
}

func TestFSStoreEnsureGitIgnore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "faradai_gitignore_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	gitIgnorePath := filepath.Join(tempDir, ".gitignore")
	initialContent := "faradaiwire\nlogs/\n"
	if err := os.WriteFile(gitIgnorePath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to create initial .gitignore: %v", err)
	}

	store, _ := NewFSStore(filepath.Join(tempDir, "protocols"))
	if err := store.EnsureGitIgnore(tempDir); err != nil {
		t.Fatalf("EnsureGitIgnore failed: %v", err)
	}

	data, _ := os.ReadFile(gitIgnorePath)
	content := string(data)
	if !strings.Contains(content, "protocols/") {
		t.Fatalf("Expected protocols/ in .gitignore, got: %s", content)
	}

	// Run again to test idempotency
	if err := store.EnsureGitIgnore(tempDir); err != nil {
		t.Fatalf("EnsureGitIgnore second run failed: %v", err)
	}

	data2, _ := os.ReadFile(gitIgnorePath)
	count := strings.Count(string(data2), "protocols/")
	if count > 2 { // "protocols/\n/protocols/\n" is 2 entries
		t.Fatalf("Expected idempotent .gitignore entries, count was %d", count)
	}
}

func TestProtocolAuthTokenAndHeaders(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "faradai_proto_headers_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFSStore(tempDir)
	if err != nil {
		t.Fatalf("NewFSStore failed: %v", err)
	}

	p := &Protocol{
		ID:           "context7-custom",
		Name:         "Context7 with Custom Headers",
		Type:         "sse",
		URLOrCommand: "https://mcp.context7.com/mcp",
		AuthToken:    "ctx7_secret_token_value_12345",
		Headers: map[string]string{
			"X-API-Key":        "secret_api_key_abcde",
			"X-Workspace-Id":   "workspace-999",
			"Authorization":    "Bearer custom_bearer_token_xyz",
			"X-Dynamic-Header": "${FARADAI_WIRE_TEST_TENANT_ID}",
		},
	}

	if err := store.Save(p); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Get(p.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if loaded.AuthToken != "ctx7_secret_token_value_12345" {
		t.Errorf("AuthToken not persisted correctly, got: %s", loaded.AuthToken)
	}
	if len(loaded.Headers) != 4 {
		t.Errorf("Expected 4 headers, got: %d", len(loaded.Headers))
	}
	if loaded.Headers["X-API-Key"] != "secret_api_key_abcde" {
		t.Errorf("X-API-Key mismatch, got: %s", loaded.Headers["X-API-Key"])
	}

	// Test MaskSecrets
	masked := loaded.MaskSecrets()
	if strings.Contains(masked.AuthToken, "secret_token_value") {
		t.Errorf("AuthToken was not masked: %s", masked.AuthToken)
	}
	if !strings.Contains(masked.AuthToken, "••••••") {
		t.Errorf("AuthToken missing mask dots: %s", masked.AuthToken)
	}
	if strings.Contains(masked.Headers["X-API-Key"], "secret_api_key") {
		t.Errorf("X-API-Key was not masked: %s", masked.Headers["X-API-Key"])
	}
	if strings.Contains(masked.Headers["Authorization"], "custom_bearer_token") {
		t.Errorf("Authorization header was not masked: %s", masked.Headers["Authorization"])
	}
	// Non-sensitive header preserved
	if masked.Headers["X-Workspace-Id"] != "workspace-999" {
		t.Errorf("Non-sensitive header should not be masked, got: %s", masked.Headers["X-Workspace-Id"])
	}
	// Dynamic header reference preserved
	if masked.Headers["X-Dynamic-Header"] != "${FARADAI_WIRE_TEST_TENANT_ID}" {
		t.Errorf("Dynamic header reference should not be masked, got: %s", masked.Headers["X-Dynamic-Header"])
	}

	// Test Dynamic Variable Resolution
	t.Setenv("FARADAI_WIRE_TEST_TENANT_ID", "tenant-eu-prod-42")
	t.Setenv("FARADAI_WIRE_TEST_AUTH", "expanded-secret-token")

	pWithEnv := &Protocol{
		ID:        "dynamic-env-test",
		Name:      "Dynamic Env Test",
		AuthToken: "${FARADAI_WIRE_TEST_AUTH}",
		Headers: map[string]string{
			"X-Tenant": "${FARADAI_WIRE_TEST_TENANT_ID}",
		},
	}
	if pWithEnv.GetResolvedAuthToken() != "expanded-secret-token" {
		t.Errorf("GetResolvedAuthToken failed, got: %s", pWithEnv.GetResolvedAuthToken())
	}
	resHeaders := pWithEnv.GetResolvedHeaders()
	if resHeaders["X-Tenant"] != "tenant-eu-prod-42" {
		t.Errorf("GetResolvedHeaders failed, got: %s", resHeaders["X-Tenant"])
	}
}

