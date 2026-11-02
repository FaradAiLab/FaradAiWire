package proxy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestMemoryCorrelationStore_BasicOperations(t *testing.T) {
	store := NewMemoryCorrelationStore()

	key := NewCorrelationKey("sess-1", "req-100")
	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pending := PendingRequest{
		UserCtx:   &filter.UserContext{UserID: "alice"},
		Context:   reqCtx,
		ToolName:  "exec_tool",
		AgentName: "agent-1",
		TraceID:   "trace-xyz",
		Timestamp: time.Now(),
	}

	// 1. Put entry
	store.Put(key, &pending)
	if store.Count() != 1 {
		t.Fatalf("expected count 1, got %d", store.Count())
	}

	// 2. GetAndRemove existing entry (O(1))
	retrieved, ok := store.GetAndRemove(key)
	if !ok || retrieved == nil {
		t.Fatalf("expected entry to exist")
	}
	if retrieved.ToolName != "exec_tool" {
		t.Errorf("expected toolName 'exec_tool', got '%s'", retrieved.ToolName)
	}
	if retrieved.UserCtx.UserID != "alice" {
		t.Errorf("expected userID 'alice', got '%s'", retrieved.UserCtx.UserID)
	}

	// Store must be empty after GetAndRemove
	if store.Count() != 0 {
		t.Errorf("expected count 0 after GetAndRemove, got %d", store.Count())
	}

	// 3. Second GetAndRemove returns false
	_, okSecond := store.GetAndRemove(key)
	if okSecond {
		t.Errorf("expected second GetAndRemove to return false")
	}
}

func TestMemoryCorrelationStore_Cleanup(t *testing.T) {
	store := NewMemoryCorrelationStore()

	oldKey := NewCorrelationKey("sess-old", "req-1")
	freshKey := NewCorrelationKey("sess-fresh", "req-2")

	store.Put(oldKey, &PendingRequest{
		ToolName:  "old_tool",
		Timestamp: time.Now().Add(-10 * time.Minute),
	})
	store.Put(freshKey, &PendingRequest{
		ToolName:  "fresh_tool",
		Timestamp: time.Now(),
	})

	if store.Count() != 2 {
		t.Fatalf("expected initial count 2, got %d", store.Count())
	}

	// Cleanup older than 5 minutes
	store.Cleanup(5 * time.Minute)

	if store.Count() != 1 {
		t.Fatalf("expected count 1 after cleanup, got %d", store.Count())
	}

	// Verify old key was purged
	if _, ok := store.GetAndRemove(oldKey); ok {
		t.Errorf("expected oldKey to be purged")
	}

	// Verify fresh key still exists
	if _, ok := store.GetAndRemove(freshKey); !ok {
		t.Errorf("expected freshKey to still exist")
	}
}

func TestMemoryCorrelationStore_HighConcurrency(t *testing.T) {
	store := NewMemoryCorrelationStore()
	workers := 50
	iterations := 200

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := NewCorrelationKey(
					fmt.Sprintf("sess-%d", workerID),
					fmt.Sprintf("req-%d", i),
				)
				store.Put(key, &PendingRequest{
					ToolName:  fmt.Sprintf("tool-%d", i),
					Timestamp: time.Now(),
				})

				retrieved, ok := store.GetAndRemove(key)
				if !ok || retrieved == nil || retrieved.ToolName != fmt.Sprintf("tool-%d", i) {
					t.Errorf("worker %d: correlation mismatch or missing for req-%d", workerID, i)
				}
			}
		}(w)
	}

	wg.Wait()

	if store.Count() != 0 {
		t.Errorf("expected store count 0 after concurrent put/remove, got %d", store.Count())
	}
}
