package session

import (
	"context"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// CorrelationKey deterministically identifies a client session and in-flight request pair.
type CorrelationKey struct {
	SessionID string
	RequestID string
}

// NewCorrelationKey creates a CorrelationKey from string identifiers.
func NewCorrelationKey(sessionID, requestID string) CorrelationKey {
	return CorrelationKey{
		SessionID: sessionID,
		RequestID: requestID,
	}
}

func (k CorrelationKey) String() string {
	return k.SessionID + ":" + k.RequestID
}

// PendingRequest stores contextual metadata for an in-flight request awaiting its response.
type PendingRequest struct {
	UserCtx   *filter.UserContext
	Context   context.Context // Preserved inbound HTTP request context (r.Context())
	ToolName  string
	AgentName string
	TraceID   string
	Timestamp time.Time
}

// CorrelationStore abstracts thread-safe, O(1) request-to-response correlation.
type CorrelationStore interface {
	Put(key CorrelationKey, req *PendingRequest)
	GetAndRemove(key CorrelationKey) (*PendingRequest, bool)
	Remove(key CorrelationKey)
	Cleanup(maxAge time.Duration)
	Clear()
	Count() int
}

// MemoryCorrelationStore implements CorrelationStore backed by a sync.RWMutex-guarded map.
type MemoryCorrelationStore struct {
	mu      sync.RWMutex
	entries map[CorrelationKey]*PendingRequest
}

// NewMemoryCorrelationStore creates a new MemoryCorrelationStore.
func NewMemoryCorrelationStore() *MemoryCorrelationStore {
	return &MemoryCorrelationStore{
		entries: make(map[CorrelationKey]*PendingRequest),
	}
}

// Put records an in-flight request under the given correlation key.
func (s *MemoryCorrelationStore) Put(key CorrelationKey, req *PendingRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = req
}

// GetAndRemove performs an O(1) retrieval and atomic deletion of the pending request.
func (s *MemoryCorrelationStore) GetAndRemove(key CorrelationKey) (*PendingRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.entries[key]
	if ok {
		delete(s.entries, key)
	}
	return req, ok
}

// Remove deletes an entry under the specified correlation key.
func (s *MemoryCorrelationStore) Remove(key CorrelationKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// Cleanup purges entries older than maxAge to prevent memory leaks from abandoned requests.
func (s *MemoryCorrelationStore) Cleanup(maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.entries {
		if v != nil && now.Sub(v.Timestamp) > maxAge {
			delete(s.entries, k)
		}
	}
}

// Clear purges all entries in the store.
func (s *MemoryCorrelationStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[CorrelationKey]*PendingRequest)
}

// Count returns the number of active correlation entries in the store.
func (s *MemoryCorrelationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
