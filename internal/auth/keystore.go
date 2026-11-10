package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrKeyNotFound is returned when an API key ID does not exist.
	ErrKeyNotFound = errors.New("api key not found")
	// ErrInvalidRole is returned when an invalid or empty role is provided.
	ErrInvalidRole = errors.New("invalid or empty role")
	// ErrInvalidName is returned when an invalid or empty key name is provided.
	ErrInvalidName = errors.New("invalid or empty key name")
)

// StoredAPIKey represents an internal persisted API key record with salted hash.
// RawKey is preserved with 0600 file permissions for local workstation reveal (ADR-0031).
type StoredAPIKey struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	AgentName    string        `json:"agent_name"`        // Bound Agent (e.g. "Claude", "coder") or "*"
	Prefix       string        `json:"prefix"`            // e.g. "faw_live_a89c" (first 12 chars of raw key)
	RawKey       string        `json:"raw_key,omitempty"` // Preserved for local workstation reveal (ADR-0031)
	Hash         string        `json:"hash"`              // hex-encoded SHA-256(salt + ":" + rawToken)
	Salt         string        `json:"salt"`              // hex-encoded random 16-byte salt
	Role         string        `json:"role"`              // "Developer", "Admin", etc.
	CreatedAt    time.Time     `json:"created_at"`
	LastUsedAt   time.Time     `json:"last_used_at"`
	Revoked      bool          `json:"revoked"`
	lastUsedNano *atomic.Int64 `json:"-"` // in-memory atomic timestamp for zero-contention updates
	hashBytes    [32]byte      `json:"-"` // cached decoded SHA-256 hash bytes for zero-alloc constant-time compare
}

func (k *StoredAPIKey) initMemory() {
	if k == nil {
		return
	}
	if k.AgentName == "" {
		k.AgentName = "*"
	}
	if k.lastUsedNano == nil {
		k.lastUsedNano = new(atomic.Int64)
		if !k.LastUsedAt.IsZero() {
			k.lastUsedNano.Store(k.LastUsedAt.UnixNano())
		}
	}
	if k.Hash != "" {
		_, _ = hex.Decode(k.hashBytes[:], []byte(k.Hash))
	}
}

// GetLastUsedAt returns the latest LastUsedAt timestamp, prioritizing buffered in-memory updates.
func (k *StoredAPIKey) GetLastUsedAt() time.Time {
	if k == nil {
		return time.Time{}
	}
	if k.lastUsedNano != nil {
		if nano := k.lastUsedNano.Load(); nano > 0 {
			return time.Unix(0, nano).UTC()
		}
	}
	return k.LastUsedAt
}

// KeyMetadata exposes metadata for administrative queries and local workstation reveal (ADR-0031).
type KeyMetadata struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	AgentName  string    `json:"agent_name"`
	Prefix     string    `json:"prefix"`
	RawKey     string    `json:"raw_key,omitempty"`
	Role       string    `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Revoked    bool      `json:"revoked"`
}

// ToMetadata converts a StoredAPIKey into safe KeyMetadata with latest LastUsedAt.
func (k *StoredAPIKey) ToMetadata() *KeyMetadata {
	if k == nil {
		return nil
	}
	agent := k.AgentName
	if agent == "" {
		agent = "*"
	}
	return &KeyMetadata{
		ID:         k.ID,
		Name:       k.Name,
		AgentName:  agent,
		Prefix:     k.Prefix,
		RawKey:     k.RawKey,
		Role:       k.Role,
		CreatedAt:  k.CreatedAt,
		LastUsedAt: k.GetLastUsedAt(),
		Revoked:    k.Revoked,
	}
}

// KeyValidator defines the read-only contract for token authentication.
type KeyValidator interface {
	ValidateKey(rawToken string) (*StoredAPIKey, bool)
}

// KeyStore defines the management contract for API key generation, validation, and revocation.
type KeyStore interface {
	KeyValidator
	GenerateKey(name, role string, agentName ...string) (rawToken string, record *StoredAPIKey, err error)
	RevokeKey(id string) error
	ListKeys() []*KeyMetadata
	GetKey(id string) (*KeyMetadata, error)
	Load() error
	Save() error
	FlushDirty() error
}

type storagePayload struct {
	APIKeys []*StoredAPIKey `json:"api_keys"`
}

// FileKeyStore implements KeyStore backed by an atomic local JSON file with in-memory usage buffering.
type FileKeyStore struct {
	filePath          string
	mu                sync.RWMutex
	keys              map[string]*StoredAPIKey // ID -> StoredAPIKey
	dirty             atomic.Bool              // tracks whether in-memory LastUsedAt updates require disk flush
	lastModUnix       int64
	lastSize          int64
	lastStatCheckUnix atomic.Int64
}

// IsDirty reports whether the keystore has in-memory modifications awaiting persistence.
func (f *FileKeyStore) IsDirty() bool {
	return f.dirty.Load()
}

// NewFileKeyStore initializes or loads a FileKeyStore at the designated path.
func NewFileKeyStore(filePath string) (*FileKeyStore, error) {
	if filePath == "" {
		return nil, errors.New("keystore file path cannot be empty")
	}

	fs := &FileKeyStore{
		filePath: filePath,
		keys:     make(map[string]*StoredAPIKey),
	}

	if err := fs.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load keystore from %s: %w", filePath, err)
	}

	return fs, nil
}

// NewMemoryKeyStore creates an in-memory KeyStore primarily for testing and ephemeral setups.
func NewMemoryKeyStore() *FileKeyStore {
	return &FileKeyStore{
		keys: make(map[string]*StoredAPIKey),
	}
}

// Load reads and parses the JSON key storage from disk.
func (f *FileKeyStore) Load() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loadLocked()
}

func (f *FileKeyStore) loadLocked() error {
	if f.filePath == "" {
		return nil
	}

	info, statErr := os.Stat(f.filePath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			f.lastModUnix = 0
			f.lastSize = 0
			return nil
		}
		return statErr
	}

	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var payload storagePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal api_keys.json: %w", err)
	}

	loaded := make(map[string]*StoredAPIKey, len(payload.APIKeys))
	for _, k := range payload.APIKeys {
		if k != nil && k.ID != "" {
			k.initMemory()
			if old, ok := f.keys[k.ID]; ok && old != nil && old.lastUsedNano != nil && k.lastUsedNano != nil {
				if oldNano := old.lastUsedNano.Load(); oldNano > k.lastUsedNano.Load() {
					k.lastUsedNano.Store(oldNano)
				}
			}
			loaded[k.ID] = k
		}
	}

	f.keys = loaded
	f.lastModUnix = info.ModTime().UnixNano()
	f.lastSize = info.Size()
	return nil
}

// reloadIfChanged checks disk metadata (throttled unless force=true) and reloads api_keys.json
// when modified by another process (such as `faradaiwire adopt` updating keys while the daemon runs).
func (f *FileKeyStore) reloadIfChanged(force bool) bool {
	if f.filePath == "" {
		return false
	}

	now := time.Now().UnixNano()
	if !force {
		prev := f.lastStatCheckUnix.Load()
		if now-prev < int64(time.Second) {
			return false
		}
		if !f.lastStatCheckUnix.CompareAndSwap(prev, now) {
			return false
		}
	} else {
		f.lastStatCheckUnix.Store(now)
	}

	info, err := os.Stat(f.filePath)
	if err != nil {
		return false
	}
	modUnix := info.ModTime().UnixNano()
	size := info.Size()

	f.mu.RLock()
	unchanged := modUnix == f.lastModUnix && size == f.lastSize
	f.mu.RUnlock()
	if unchanged {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if modUnix == f.lastModUnix && size == f.lastSize {
		return false
	}
	return f.loadLocked() == nil
}

// reloadIfChangedLocked must be called with f.mu.Lock() held.
func (f *FileKeyStore) reloadIfChangedLocked() bool {
	if f.filePath == "" {
		return false
	}
	info, err := os.Stat(f.filePath)
	if err != nil {
		return false
	}
	if info.ModTime().UnixNano() == f.lastModUnix && info.Size() == f.lastSize {
		return false
	}
	return f.loadLocked() == nil
}

func (f *FileKeyStore) syncLastUsedLocked() {
	for _, k := range f.keys {
		if k != nil && k.lastUsedNano != nil {
			if nano := k.lastUsedNano.Load(); nano > 0 {
				k.LastUsedAt = time.Unix(0, nano).UTC()
			}
		}
	}
}

// Save writes the current key state atomically to disk with 0600 permissions.
func (f *FileKeyStore) Save() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	_ = f.reloadIfChangedLocked()
	f.syncLastUsedLocked()

	if err := f.saveLocked(); err != nil {
		return err
	}

	f.dirty.Store(false)
	return nil
}

// FlushDirty atomically persists buffered in-memory keystore updates to disk if dirty,
// reloading any external additions/revocations before writing so external keys are never overwritten.
func (f *FileKeyStore) FlushDirty() error {
	if !f.dirty.Load() {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.dirty.Load() {
		return nil
	}

	_ = f.reloadIfChangedLocked()
	f.syncLastUsedLocked()

	if err := f.saveLocked(); err != nil {
		return err
	}

	f.dirty.Store(false)
	return nil
}

// Close flushes any pending keystore writes to disk.
func (f *FileKeyStore) Close() error {
	return f.FlushDirty()
}

func (f *FileKeyStore) saveLocked() error {
	if f.filePath == "" {
		return nil
	}

	dir := filepath.Dir(f.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create keystore directory %s: %w", dir, err)
	}

	keyList := make([]*StoredAPIKey, 0, len(f.keys))
	for _, k := range f.keys {
		keyList = append(keyList, k)
	}

	payload := storagePayload{
		APIKeys: keyList,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore payload: %w", err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", f.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary keystore file: %w", err)
	}

	if err := os.Rename(tmpFile, f.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomic replace keystore file: %w", err)
	}
	if info, statErr := os.Stat(f.filePath); statErr == nil {
		f.lastModUnix = info.ModTime().UnixNano()
		f.lastSize = info.Size()
	}

	return nil
}

// GenerateKey produces a new cryptographically secure API key and persists its salted hash and raw token.
// Plaintext token format: faw_live_<32 hex chars> (total 40 chars).
// Preserves raw token under POSIX 0600 file permissions for local workstation reveal (ADR-0031).
func (f *FileKeyStore) GenerateKey(name, role string, agentName ...string) (string, *StoredAPIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, ErrInvalidName
	}
	role = strings.TrimSpace(role)
	if role == "" {
		return "", nil, ErrInvalidRole
	}
	targetAgent := "*"
	if len(agentName) > 0 && strings.TrimSpace(agentName[0]) != "" {
		targetAgent = strings.TrimSpace(agentName[0])
	}

	// 1. Generate 16 random bytes for the token secret
	rawBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key token: %w", err)
	}
	rawToken := "faw_live_" + hex.EncodeToString(rawBytes)

	// 2. Extract prefix (e.g. "faw_live_a89c" -> first 12 characters)
	prefix := rawToken
	if len(rawToken) >= 12 {
		prefix = rawToken[:12]
	}

	// 3. Generate 16 random bytes for salt
	saltBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, saltBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	saltHex := hex.EncodeToString(saltBytes)

	// 4. Compute salted SHA-256 hash
	computedHash := ComputeHash(saltHex, rawToken)

	// 5. Generate random key ID
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key ID: %w", err)
	}
	id := fmt.Sprintf("key_%d%s", time.Now().Unix(), hex.EncodeToString(idBytes))

	record := &StoredAPIKey{
		ID:         id,
		Name:       name,
		AgentName:  targetAgent,
		Prefix:     prefix,
		RawKey:     rawToken,
		Hash:       computedHash,
		Salt:       saltHex,
		Role:       role,
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Time{},
		Revoked:    false,
	}
	record.initMemory()

	f.mu.Lock()
	_ = f.reloadIfChangedLocked()
	f.syncLastUsedLocked()
	f.keys[id] = record
	err := f.saveLocked()
	if err == nil {
		f.dirty.Store(false)
	}
	f.mu.Unlock()

	if err != nil {
		return "", nil, err
	}

	// Return a defensive copy of record
	recCopy := *record
	return rawToken, &recCopy, nil
}

// ValidateKey validates an incoming raw token against registered unrevoked keys in constant time.
// If valid, updates LastUsedAt in memory without disk I/O or background goroutine allocations (SEC-018 / DEC-06).
// On lookup miss (or once per second on disk change), reloads api_keys.json transparently so keys created
// externally (e.g. `faradaiwire adopt`) take effect without restarting a running daemon.
func (f *FileKeyStore) ValidateKey(rawToken string) (*StoredAPIKey, bool) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, false
	}

	if f.filePath != "" {
		f.reloadIfChanged(false)
	}

	if keyCopy, ok := f.validateCachedKey(rawToken); ok {
		return keyCopy, true
	}

	if f.filePath != "" && f.reloadIfChanged(true) {
		return f.validateCachedKey(rawToken)
	}
	return nil, false
}

func (f *FileKeyStore) validateCachedKey(rawToken string) (*StoredAPIKey, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var matchedKey *StoredAPIKey
	for _, k := range f.keys {
		if k == nil || k.Revoked {
			continue
		}

		// Candidate hash computation (zero allocations on stack)
		expectedSum := ComputeHashSum(k.Salt, rawToken)

		// Constant-time comparison
		if subtle.ConstantTimeCompare(expectedSum[:], k.hashBytes[:]) == 1 {
			matchedKey = k
			break
		}
	}

	if matchedKey == nil {
		return nil, false
	}

	now := time.Now().UTC()
	if matchedKey.lastUsedNano != nil {
		matchedKey.lastUsedNano.Store(now.UnixNano())
	}
	f.dirty.Store(true)

	keyCopy := *matchedKey
	keyCopy.LastUsedAt = now
	return &keyCopy, true
}

// RevokeKey immediately invalidates an API key by ID.
func (f *FileKeyStore) RevokeKey(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	_ = f.reloadIfChangedLocked()
	k, exists := f.keys[id]
	if !exists {
		return ErrKeyNotFound
	}

	f.syncLastUsedLocked()

	k.Revoked = true
	if err := f.saveLocked(); err != nil {
		return err
	}
	f.dirty.Store(false)
	return nil
}

// ListKeys returns all keys as metadata without exposing hashes or salts.
func (f *FileKeyStore) ListKeys() []*KeyMetadata {
	if f.filePath != "" {
		f.reloadIfChanged(true)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	list := make([]*KeyMetadata, 0, len(f.keys))
	for _, k := range f.keys {
		if k != nil {
			list = append(list, k.ToMetadata())
		}
	}
	return list
}

// GetKey returns metadata for a single key by ID.
func (f *FileKeyStore) GetKey(id string) (*KeyMetadata, error) {
	if f.filePath != "" {
		f.reloadIfChanged(true)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	k, exists := f.keys[id]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return k.ToMetadata(), nil
}

// ComputeHashSum calculates sha256(salt + ":" + rawToken) into a 32-byte array with zero heap allocations.
func ComputeHashSum(salt, rawToken string) [32]byte {
	var buf [128]byte
	totalLen := len(salt) + 1 + len(rawToken)
	if totalLen <= len(buf) {
		n := copy(buf[:], salt)
		buf[n] = ':'
		n++
		copy(buf[n:], rawToken)
		return sha256.Sum256(buf[:totalLen])
	}
	// Fallback for unusually long tokens
	b := make([]byte, totalLen)
	n := copy(b, salt)
	b[n] = ':'
	n++
	copy(b[n:], rawToken)
	return sha256.Sum256(b)
}

// ComputeHash calculates hex(sha256(salt + ":" + token)).
func ComputeHash(salt, rawToken string) string {
	sum := ComputeHashSum(salt, rawToken)
	return hex.EncodeToString(sum[:])
}
