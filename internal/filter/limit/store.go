package limit

import (
	"context"
	"sync"
	"time"
)

// Default configuration constants for InMemoryStateStore.
const (
	DefaultStoreTTL             = 5 * time.Minute
	DefaultStoreCleanupInterval = 60 * time.Second
	DefaultStoreMaxKeys         = 10000
)

// ToolCall represents a record of a single tool execution.
type ToolCall struct {
	Name      string    `json:"name"`
	ArgsHash  string    `json:"args_hash"`
	Timestamp time.Time `json:"timestamp"`
}

// StateStore defines the storage contract for rate-limiting and loop protection filters.
type StateStore interface {
	// TakeToken attempts to consume 1 token for the given key.
	// It applies the token-bucket refill logic using maxBurst and refillRate.
	// Returns true if a token was successfully consumed, false otherwise.
	TakeToken(ctx context.Context, key string, maxBurst int, refillRate float64) (bool, error)

	// AddAndGetToolCalls adds a new tool call to history for the given key
	// and returns only the calls that fall within the active sliding window duration.
	AddAndGetToolCalls(ctx context.Context, key string, call ToolCall, window time.Duration) ([]ToolCall, error)
}

type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
	lastActive time.Time
}

type toolHistoryEntry struct {
	calls      []ToolCall
	lastActive time.Time
}

// StoreOption configures InMemoryStateStore behavior.
type StoreOption func(*InMemoryStateStore)

// WithTTL sets the expiration duration for idle state entries.
func WithTTL(ttl time.Duration) StoreOption {
	return func(s *InMemoryStateStore) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithCleanupInterval sets the period between periodic background eviction sweeps.
func WithCleanupInterval(interval time.Duration) StoreOption {
	return func(s *InMemoryStateStore) {
		if interval > 0 {
			s.cleanupInterval = interval
		}
	}
}

// WithMaxKeys sets the maximum upper bound on tracking entries before LRU eviction.
func WithMaxKeys(maxKeys int) StoreOption {
	return func(s *InMemoryStateStore) {
		if maxKeys > 0 {
			s.maxKeys = maxKeys
		}
	}
}

// WithNowFunc injects a custom clock provider (useful for deterministic testing).
func WithNowFunc(fn func() time.Time) StoreOption {
	return func(s *InMemoryStateStore) {
		if fn != nil {
			s.nowFunc = fn
		}
	}
}

// WithDisableBackgroundWorker disables the automated background eviction goroutine.
func WithDisableBackgroundWorker() StoreOption {
	return func(s *InMemoryStateStore) {
		s.disableWorker = true
	}
}

// InMemoryStateStore is a thread-safe, memory-bounded in-memory implementation of StateStore.
// It tracks lastActive timestamps for all entries, runs periodic background TTL sweeps,
// and enforces LRU eviction when maximum cardinality limits are exceeded.
type InMemoryStateStore struct {
	mu              sync.Mutex
	buckets         map[string]*tokenBucket
	toolHistories   map[string]*toolHistoryEntry
	ttl             time.Duration
	cleanupInterval time.Duration
	maxKeys         int
	nowFunc         func() time.Time
	disableWorker   bool

	stopChan  chan struct{}
	doneChan  chan struct{}
	closeOnce sync.Once
	closed    bool
}

// NewInMemoryStateStore creates a new InMemoryStateStore with options.
func NewInMemoryStateStore(opts ...StoreOption) *InMemoryStateStore {
	s := &InMemoryStateStore{
		buckets:         make(map[string]*tokenBucket),
		toolHistories:   make(map[string]*toolHistoryEntry),
		ttl:             DefaultStoreTTL,
		cleanupInterval: DefaultStoreCleanupInterval,
		maxKeys:         DefaultStoreMaxKeys,
		nowFunc:         time.Now,
		stopChan:        make(chan struct{}),
		doneChan:        make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	if !s.disableWorker {
		s.startBackgroundWorker()
	}

	return s
}

func (s *InMemoryStateStore) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

func (s *InMemoryStateStore) startBackgroundWorker() {
	go func() {
		defer close(s.doneChan)
		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				s.EvictExpired(s.now())
			}
		}
	}()
}

// TakeToken implements StateStore for local memory.
func (s *InMemoryStateStore) TakeToken(ctx context.Context, key string, maxBurst int, refillRate float64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false, nil
	}

	now := s.now()
	bucket, exists := s.buckets[key]
	if !exists {
		// Enforce bounded memory upper limit
		if len(s.buckets) >= s.maxKeys {
			s.pruneExpiredBucketsLocked(now)
			if len(s.buckets) >= s.maxKeys {
				s.evictLRUBucketLocked()
			}
		}

		bucket = &tokenBucket{
			tokens:     float64(maxBurst),
			maxTokens:  float64(maxBurst),
			refillRate: refillRate,
			lastRefill: now,
			lastActive: now,
		}
		s.buckets[key] = bucket
	}

	// Refill tokens based on time elapsed
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * refillRate
		if bucket.tokens > bucket.maxTokens {
			bucket.tokens = bucket.maxTokens
		}
		bucket.lastRefill = now
	}
	bucket.lastActive = now

	// Check if bucket has at least 1 token
	if bucket.tokens < 1.0 {
		return false, nil
	}

	// Consume 1 token
	bucket.tokens -= 1.0
	return true, nil
}

// AddAndGetToolCalls implements StateStore for local memory.
func (s *InMemoryStateStore) AddAndGetToolCalls(ctx context.Context, key string, call ToolCall, window time.Duration) ([]ToolCall, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, nil
	}

	now := s.now()
	cutoff := now.Add(-window)

	entry, exists := s.toolHistories[key]
	if !exists {
		// Enforce bounded memory upper limit
		if len(s.toolHistories) >= s.maxKeys {
			s.pruneExpiredHistoriesLocked(now)
			if len(s.toolHistories) >= s.maxKeys {
				s.evictLRUToolHistoryLocked()
			}
		}
		entry = &toolHistoryEntry{}
		s.toolHistories[key] = entry
	}

	// Clean up old history for this user and append current call
	var activeCalls []ToolCall
	for _, c := range entry.calls {
		if c.Timestamp.After(cutoff) {
			activeCalls = append(activeCalls, c)
		}
	}

	activeCalls = append(activeCalls, call)
	entry.calls = activeCalls
	entry.lastActive = now

	// Return a copy so caller modifications don't cause data races
	result := make([]ToolCall, len(activeCalls))
	copy(result, activeCalls)
	return result, nil
}

// EvictExpired sweeps the store and deletes entries that have been idle longer than the configured TTL.
// Returns the total number of evicted entries.
func (s *InMemoryStateStore) EvictExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	evicted := s.pruneExpiredBucketsLocked(now)
	evicted += s.pruneExpiredHistoriesLocked(now)
	return evicted
}

func (s *InMemoryStateStore) pruneExpiredBucketsLocked(now time.Time) int {
	evicted := 0
	for key, b := range s.buckets {
		if now.Sub(b.lastActive) > s.ttl {
			delete(s.buckets, key)
			evicted++
		}
	}
	return evicted
}

func (s *InMemoryStateStore) pruneExpiredHistoriesLocked(now time.Time) int {
	evicted := 0
	for key, h := range s.toolHistories {
		if now.Sub(h.lastActive) > s.ttl {
			delete(s.toolHistories, key)
			evicted++
		}
	}
	return evicted
}

func (s *InMemoryStateStore) evictLRUBucketLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, b := range s.buckets {
		if first || b.lastActive.Before(oldestTime) {
			oldestTime = b.lastActive
			oldestKey = key
			first = false
		}
	}
	if !first {
		delete(s.buckets, oldestKey)
	}
}

func (s *InMemoryStateStore) evictLRUToolHistoryLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, h := range s.toolHistories {
		if first || h.lastActive.Before(oldestTime) {
			oldestTime = h.lastActive
			oldestKey = key
			first = false
		}
	}
	if !first {
		delete(s.toolHistories, oldestKey)
	}
}

// BucketCount returns the current number of active rate limit buckets.
func (s *InMemoryStateStore) BucketCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}

// HistoryCount returns the current number of active tool history records.
func (s *InMemoryStateStore) HistoryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.toolHistories)
}

// Close stops the background eviction worker and marks the store as closed.
func (s *InMemoryStateStore) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()

		if !s.disableWorker {
			close(s.stopChan)
			<-s.doneChan
		}
	})
	return nil
}
