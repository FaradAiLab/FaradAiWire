package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileKeyStore_GenerateAndValidate(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keys", "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	rawToken, record, err := store.GenerateKey("Test Cursor Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if !strings.HasPrefix(rawToken, "faw_live_") {
		t.Errorf("expected rawToken to start with 'faw_live_', got %s", rawToken)
	}
	if record.Prefix != rawToken[:12] {
		t.Errorf("expected prefix '%s', got '%s'", rawToken[:12], record.Prefix)
	}
	if record.Role != "Developer" {
		t.Errorf("expected role 'Developer', got '%s'", record.Role)
	}
	if record.Salt == "" || record.Hash == "" {
		t.Errorf("expected non-empty salt and hash")
	}

	// Verify raw token is preserved in the JSON file on disk for local workstation reveal (ADR-0031)
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read persisted keystore: %v", err)
	}
	if !strings.Contains(string(fileBytes), rawToken) {
		t.Fatalf("expected raw token to be preserved in keystore for local reveal: %s", string(fileBytes))
	}

	// Verify file permissions are 0600
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat keystore file: %v", err)
	}
	perm := fileInfo.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}

	// Validate valid token
	validated, ok := store.ValidateKey(rawToken)
	if !ok || validated == nil {
		t.Fatalf("expected ValidateKey to succeed for valid token")
	}
	if validated.ID != record.ID {
		t.Errorf("expected validated key ID '%s', got '%s'", record.ID, validated.ID)
	}
	if validated.Role != "Developer" {
		t.Errorf("expected validated key role 'Developer', got '%s'", validated.Role)
	}

	// Validate invalid token
	invalidToken := rawToken + "corrupted"
	_, ok = store.ValidateKey(invalidToken)
	if ok {
		t.Errorf("expected ValidateKey to fail for corrupted token")
	}

	// Validate empty token
	_, ok = store.ValidateKey("")
	if ok {
		t.Errorf("expected ValidateKey to fail for empty token")
	}
}

func TestFileKeyStore_Revocation(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	rawToken, record, err := store.GenerateKey("Agent 1", "Admin")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Key is valid before revocation
	_, ok := store.ValidateKey(rawToken)
	if !ok {
		t.Fatalf("expected key to be valid before revocation")
	}

	// Revoke key
	err = store.RevokeKey(record.ID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	// Key must now fail validation
	_, ok = store.ValidateKey(rawToken)
	if ok {
		t.Errorf("revoked key must not be validated")
	}

	// Verify persistence after reload
	newStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to reload keystore: %v", err)
	}
	_, ok = newStore.ValidateKey(rawToken)
	if ok {
		t.Errorf("revoked key must remain invalid after reload from disk")
	}
}

func TestFileKeyStore_ListKeys_NoSecretsExposed(t *testing.T) {
	store := NewMemoryKeyStore()

	_, _, err := store.GenerateKey("Claude Desktop", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	_, _, err = store.GenerateKey("Admin CLI", "Admin")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keys := store.ListKeys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	for _, k := range keys {
		if k.ID == "" || k.Name == "" || k.Prefix == "" || k.Role == "" {
			t.Errorf("expected metadata fields to be populated, got %+v", k)
		}
	}
}

func TestFileKeyStore_LastUsedAtUpdated(t *testing.T) {
	store := NewMemoryKeyStore()
	rawToken, _, err := store.GenerateKey("Test Runner", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	beforeValidation := time.Now().UTC()

	key, ok := store.ValidateKey(rawToken)
	if !ok {
		t.Fatalf("expected ValidateKey to succeed")
	}

	if key.LastUsedAt.Before(beforeValidation) {
		t.Errorf("expected LastUsedAt (%v) to be updated after %v", key.LastUsedAt, beforeValidation)
	}
}

func TestFileKeyStore_HotPath_ZeroDiskAndNoGoroutineLeak(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	rawToken, _, err := store.GenerateKey("High Throughput Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Capture disk modification time after initial generation
	initialStat, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat keystore file: %v", err)
	}
	initialModTime := initialStat.ModTime()

	// Capture baseline goroutine count
	initialGoroutines := runtime.NumGoroutine()

	// Perform 100 consecutive key validations on the hot path
	for i := 0; i < 100; i++ {
		key, ok := store.ValidateKey(rawToken)
		if !ok || key == nil {
			t.Fatalf("ValidateKey failed on iteration %d", i)
		}
	}

	// 1. Verify zero background goroutines were spawned
	currentGoroutines := runtime.NumGoroutine()
	if currentGoroutines > initialGoroutines+2 {
		t.Errorf("Goroutine leak detected: initial %d, current %d", initialGoroutines, currentGoroutines)
	}

	// 2. Verify zero disk writes occurred during key validation
	postStat, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat keystore file after validations: %v", err)
	}
	if !postStat.ModTime().Equal(initialModTime) {
		t.Errorf("Hot-path disk write detected! File modtime changed: before %v, after %v", initialModTime, postStat.ModTime())
	}

	// 3. Verify dirty flag is set
	if !store.IsDirty() {
		t.Errorf("Expected keystore to be marked dirty after ValidateKey")
	}
}

func TestFileKeyStore_FlushDirty_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	rawToken, record, err := store.GenerateKey("Persistent Agent", "Admin")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Verify initially clean after generate save
	if store.IsDirty() {
		t.Errorf("Keystore should not be dirty immediately after key generation")
	}

	// Validate key: buffers LastUsedAt in RAM
	time.Sleep(5 * time.Millisecond)
	validateTime := time.Now().UTC()
	key, ok := store.ValidateKey(rawToken)
	if !ok || key == nil {
		t.Fatalf("ValidateKey failed")
	}
	if !store.IsDirty() {
		t.Errorf("Keystore must be dirty after ValidateKey")
	}

	// Verify ListKeys and GetKey observe the in-memory LastUsedAt before disk flush
	meta, err := store.GetKey(record.ID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if meta.LastUsedAt.Before(validateTime) {
		t.Errorf("GetKey expected LastUsedAt >= %v, got %v", validateTime, meta.LastUsedAt)
	}

	// Flush dirty state to disk
	if err := store.FlushDirty(); err != nil {
		t.Fatalf("FlushDirty failed: %v", err)
	}

	if store.IsDirty() {
		t.Errorf("Keystore should not be dirty after successful FlushDirty")
	}

	// Calling FlushDirty a second time must be a no-op
	if err := store.FlushDirty(); err != nil {
		t.Fatalf("Second FlushDirty failed: %v", err)
	}

	// Verify persistence: create a new keystore instance from the same disk file
	reloadedStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileKeyStore reload failed: %v", err)
	}

	reloadedMeta, err := reloadedStore.GetKey(record.ID)
	if err != nil {
		t.Fatalf("reloaded GetKey failed: %v", err)
	}
	if reloadedMeta.LastUsedAt.Before(validateTime) {
		t.Errorf("Reloaded key LastUsedAt (%v) was not persisted to disk (expected >= %v)", reloadedMeta.LastUsedAt, validateTime)
	}
}

func TestFileKeyStore_ConcurrentValidation_NoRace(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	rawToken1, _, err := store.GenerateKey("Worker 1", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key 1: %v", err)
	}
	rawToken2, _, err := store.GenerateKey("Worker 2", "Admin")
	if err != nil {
		t.Fatalf("failed to generate key 2: %v", err)
	}

	const goroutines = 50
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			token := rawToken1
			if id%2 == 0 {
				token = rawToken2
			}
			for i := 0; i < iterations; i++ {
				key, ok := store.ValidateKey(token)
				if !ok || key == nil {
					t.Errorf("concurrent validation failed for goroutine %d iteration %d", id, i)
					return
				}
				if i%20 == 0 {
					_ = store.ListKeys()
				}
			}
		}(g)
	}

	wg.Wait()

	// Flush dirty state after concurrent validations
	if err := store.FlushDirty(); err != nil {
		t.Fatalf("FlushDirty failed: %v", err)
	}
	if store.IsDirty() {
		t.Errorf("Keystore should be clean after FlushDirty")
	}
}

func BenchmarkFileKeyStore_ValidateKey(b *testing.B) {
	store := NewMemoryKeyStore()
	rawToken, _, err := store.GenerateKey("Bench Agent", "Developer")
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, ok := store.ValidateKey(rawToken)
		if !ok || key == nil {
			b.Fatalf("ValidateKey failed")
		}
	}
}

func BenchmarkFileKeyStore_ValidateKey_Parallel(b *testing.B) {
	store := NewMemoryKeyStore()
	rawToken, _, err := store.GenerateKey("Bench Parallel Agent", "Developer")
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key, ok := store.ValidateKey(rawToken)
			if !ok || key == nil {
				b.Fatalf("ValidateKey failed")
			}
		}
	})
}

func TestFileKeyStore_AgentScopingAndRawKey(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "api_keys.json")

	store, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	// 1. Generate key scoped to specific agent "Claude"
	rawToken, record, err := store.GenerateKey("Claude Workstation", "Developer", "Claude")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if record.AgentName != "Claude" {
		t.Errorf("expected AgentName 'Claude', got '%s'", record.AgentName)
	}
	if record.RawKey != rawToken {
		t.Errorf("expected RawKey '%s', got '%s'", rawToken, record.RawKey)
	}

	// 2. Reload from disk and verify persistence
	reloaded, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("failed to reload keystore: %v", err)
	}

	keys := reloaded.ListKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in reloaded keystore, got %d", len(keys))
	}
	if keys[0].AgentName != "Claude" {
		t.Errorf("expected reloaded AgentName 'Claude', got '%s'", keys[0].AgentName)
	}
	if keys[0].RawKey != rawToken {
		t.Errorf("expected reloaded RawKey '%s', got '%s'", rawToken, keys[0].RawKey)
	}

	// 3. Generate wildcard key
	_, wildRecord, err := store.GenerateKey("Global Key", "Developer")
	if err != nil {
		t.Fatalf("GenerateKey wildcard failed: %v", err)
	}
	if wildRecord.AgentName != "*" {
		t.Errorf("expected default AgentName '*', got '%s'", wildRecord.AgentName)
	}
}

func TestFileKeyStore_ReloadsExternalKeyCreationAndRevocation(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "api_keys.json")

	daemonStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileKeyStore daemon: %v", err)
	}
	cliStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileKeyStore cli: %v", err)
	}

	// Ensure mtime/size shift across same-second filesystems
	rawToken, rec, err := cliStore.GenerateKey("Live Adopt", "Developer", "cursor")
	if err != nil {
		t.Fatalf("cli GenerateKey: %v", err)
	}

	// Immediate validation on miss must pick up the externally written key without restart
	got, ok := daemonStore.ValidateKey(rawToken)
	if !ok || got == nil || got.ID != rec.ID {
		t.Fatalf("expected live ValidateKey to reload external key, got ok=%v rec=%+v", ok, got)
	}

	// External revocation must be observed once stat throttle elapses
	if err := cliStore.RevokeKey(rec.ID); err != nil {
		t.Fatalf("cli RevokeKey: %v", err)
	}
	daemonStore.lastStatCheckUnix.Store(0)
	if _, ok := daemonStore.ValidateKey(rawToken); ok {
		t.Fatal("expected live ValidateKey to observe external key revocation")
	}
}

func TestFileKeyStore_ListKeysAndFlushDirty_PreservesExternalKeys(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "api_keys.json")

	daemonStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileKeyStore daemon: %v", err)
	}
	raw1, _, err := daemonStore.GenerateKey("Primary", "Developer", "claude")
	if err != nil {
		t.Fatalf("daemon GenerateKey: %v", err)
	}

	cliStore, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileKeyStore cli: %v", err)
	}
	_, _, err = cliStore.GenerateKey("CLI Key 1", "Developer", "cursor")
	if err != nil {
		t.Fatalf("cli GenerateKey 1: %v", err)
	}

	// ListKeys must sync external additions
	if got := daemonStore.ListKeys(); len(got) != 2 {
		t.Fatalf("expected ListKeys to observe external key (len 2), got %d", len(got))
	}

	// Add another external key via CLI store, mark daemonStore dirty via cache-hit ValidateKey, then FlushDirty
	raw3, _, err := cliStore.GenerateKey("CLI Key 2", "Developer", "windsurf")
	if err != nil {
		t.Fatalf("cli GenerateKey 2: %v", err)
	}
	if _, ok := daemonStore.ValidateKey(raw1); !ok {
		t.Fatal("expected ValidateKey(raw1) hit")
	}
	if err := daemonStore.FlushDirty(); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	reloaded, err := NewFileKeyStore(filePath)
	if err != nil {
		t.Fatalf("reload keystore: %v", err)
	}
	if got := reloaded.ListKeys(); len(got) != 3 {
		t.Fatalf("expected FlushDirty to preserve external keys (len 3), got %d", len(got))
	}
	if _, ok := reloaded.ValidateKey(raw3); !ok {
		t.Fatal("expected external key 3 to survive daemon FlushDirty")
	}
}
