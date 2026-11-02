package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// AgentUsageChecker is a function callback that checks which agents (if any) are using a given protocol.
type AgentUsageChecker func(protocolID string) ([]string, error)

// Store defines the CRUD contract for persisted MCP protocol configurations.
type Store interface {
	List() ([]*Protocol, error)
	Get(id string) (*Protocol, error)
	Save(proto *Protocol) error
	Delete(id string) error
	SetAgentUsageChecker(checker AgentUsageChecker)
	EnsureGitIgnore(repoRootDir string) error
}

// FSStore implements Store using sandboxed local filesystem storage with POSIX 0600 permissions.
type FSStore struct {
	baseDir      string
	mu           sync.RWMutex
	agentChecker AgentUsageChecker
}

// NewFSStore creates a new filesystem-backed protocol store at baseDir.
func NewFSStore(baseDir string) (*FSStore, error) {
	trimmed := strings.TrimSpace(baseDir)
	if trimmed == "" {
		trimmed = "./protocols"
	}

	if err := os.MkdirAll(trimmed, 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("failed to initialize protocols directory '%s': %w", trimmed, err)
	}

	return &FSStore{
		baseDir: trimmed,
	}, nil
}

// SetAgentUsageChecker configures the referential integrity callback.
func (s *FSStore) SetAgentUsageChecker(checker AgentUsageChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentChecker = checker
}

// EnsureGitIgnore guarantees that the protocols directory is listed in the root .gitignore file.
func (s *FSStore) EnsureGitIgnore(repoRootDir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	root := strings.TrimSpace(repoRootDir)
	if root == "" {
		root = "."
	}

	gitIgnorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitIgnorePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create new .gitignore
			return os.WriteFile(gitIgnorePath, []byte("# Local MCP protocol credentials\nprotocols/\n/protocols/\n"), 0644)
		}
		return err
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	hasEntry := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "protocols/" || trimmed == "/protocols/" || trimmed == "protocols" {
			hasEntry = true
			break
		}
	}

	if !hasEntry {
		entry := "\n# Local MCP protocol credentials (added by Farad Ai)\nprotocols/\n/protocols/\n"
		f, openErr := os.OpenFile(gitIgnorePath, os.O_APPEND|os.O_WRONLY, 0644)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		if _, writeErr := f.WriteString(entry); writeErr != nil {
			return writeErr
		}
	}

	return nil
}

// Save validates and persists a protocol definition to disk with strict 0600 permissions.
func (s *FSStore) Save(p *Protocol) error {
	if p == nil {
		return errors.New("cannot save nil protocol")
	}

	if err := p.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	filePath, err := pathguard.ResolveSandboxedPath(s.baseDir, p.ID+".json")
	if err != nil {
		return fmt.Errorf("failed to resolve protocol path: %w", err)
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal protocol JSON: %w", err)
	}

	// Write directly with 0600 permissions
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write protocol file: %w", err)
	}
	// Explicit chmod to override restrictive umask
	_ = os.Chmod(filePath, 0600)

	return nil
}

// Get loads a protocol by ID.
func (s *FSStore) Get(id string) (*Protocol, error) {
	trimmedID := strings.TrimSpace(id)
	if err := pathguard.ValidateSafeIdentifier(trimmedID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath, err := pathguard.ResolveSandboxedPath(s.baseDir, trimmedID+".json")
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrProtocolNotFound
		}
		return nil, fmt.Errorf("failed to read protocol: %w", err)
	}

	var proto Protocol
	if err := json.Unmarshal(data, &proto); err != nil {
		return nil, fmt.Errorf("failed to parse protocol JSON: %w", err)
	}

	return &proto, nil
}

// List loads all protocols from disk and returns them sorted by ID.
func (s *FSStore) List() ([]*Protocol, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Protocol{}, nil
		}
		return nil, fmt.Errorf("failed to read protocols directory: %w", err)
	}

	var protocols []*Protocol
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		baseName := strings.TrimSuffix(entry.Name(), ".json")
		if err := pathguard.ValidateSafeIdentifier(baseName); err != nil {
			continue
		}

		filePath := filepath.Join(s.baseDir, entry.Name())
		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			continue
		}

		var p Protocol
		if jsonErr := json.Unmarshal(data, &p); jsonErr != nil {
			continue
		}
		protocols = append(protocols, &p)
	}

	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].ID < protocols[j].ID
	})

	return protocols, nil
}

// Delete removes a protocol file, blocking deletion if the protocol is currently referenced by agents.
func (s *FSStore) Delete(id string) error {
	trimmedID := strings.TrimSpace(id)
	if err := pathguard.ValidateSafeIdentifier(trimmedID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce referential integrity
	if s.agentChecker != nil {
		referencingAgents, err := s.agentChecker(trimmedID)
		if err != nil {
			return fmt.Errorf("failed to verify protocol dependencies: %w", err)
		}
		if len(referencingAgents) > 0 {
			return fmt.Errorf("%w: protocol '%s' is attached to agents: %s", ErrProtocolInUse, trimmedID, strings.Join(referencingAgents, ", "))
		}
	}

	filePath, err := pathguard.ResolveSandboxedPath(s.baseDir, trimmedID+".json")
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return ErrProtocolNotFound
		}
		return fmt.Errorf("failed to delete protocol file: %w", err)
	}

	return nil
}
