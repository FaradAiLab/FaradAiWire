package limit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestInMemoryStateStore_TakeToken(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	currentTime := now

	store := NewInMemoryStateStore(
		WithDisableBackgroundWorker(),
		WithNowFunc(func() time.Time { return currentTime }),
	)
	defer store.Close()

	// 1. Initial burst capacity of 3
	for i := 0; i < 3; i++ {
		allowed, err := store.TakeToken(ctx, "user1", 3, 1.0)
		if err != nil {
			t.Fatalf("unexpected error on token %d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("expected token %d to be allowed", i+1)
		}
	}

	// 2. 4th attempt should be rejected (empty bucket)
	allowed, err := store.TakeToken(ctx, "user1", 3, 1.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected 4th token to be blocked")
	}

	// 3. Advance time by 2 seconds (refill 2 tokens at rate 1.0/sec)
	currentTime = currentTime.Add(2 * time.Second)

	// Should allow 2 tokens
	for i := 0; i < 2; i++ {
		allowed, err := store.TakeToken(ctx, "user1", 3, 1.0)
		if err != nil {
			t.Fatalf("unexpected error after refill %d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("expected refill token %d to be allowed", i+1)
		}
	}

	// 3rd token after refill should be blocked
	allowed, err = store.TakeToken(ctx, "user1", 3, 1.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected 3rd token after partial refill to be blocked")
	}

	// 4. Isolated user keys
	allowedUser2, err := store.TakeToken(ctx, "user2", 3, 1.0)
	if err != nil {
		t.Fatalf("unexpected error for user2: %v", err)
	}
	if !allowedUser2 {
		t.Fatalf("expected user2 to have independent full bucket")
	}
}

func TestInMemoryStateStore_AddAndGetToolCalls(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	currentTime := now

	store := NewInMemoryStateStore(
		WithDisableBackgroundWorker(),
		WithNowFunc(func() time.Time { return currentTime }),
	)
	defer store.Close()

	call1 := ToolCall{Name: "exec_sql", ArgsHash: "hash1", Timestamp: currentTime}
	calls, err := store.AddAndGetToolCalls(ctx, "user1", call1, 10*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Advance time by 3 seconds and add second call
	currentTime = currentTime.Add(3 * time.Second)
	call2 := ToolCall{Name: "exec_sql", ArgsHash: "hash1", Timestamp: currentTime}
	calls, err = store.AddAndGetToolCalls(ctx, "user1", call2, 10*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	// Advance time past the 10-second sliding window for call1 (at t = now + 11s)
	currentTime = now.Add(11 * time.Second)
	call3 := ToolCall{Name: "exec_sql", ArgsHash: "hash1", Timestamp: currentTime}
	calls, err = store.AddAndGetToolCalls(ctx, "user1", call3, 10*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// call1 is older than 10s window (at now), call2 is at now+3s (8s old, within window), call3 is at now+11s
	if len(calls) != 2 {
		t.Fatalf("expected 2 active calls (call2 and call3), got %d", len(calls))
	}
}

func TestInMemoryStateStore_TTLEviction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	currentTime := now

	store := NewInMemoryStateStore(
		WithDisableBackgroundWorker(),
		WithTTL(5*time.Minute),
		WithNowFunc(func() time.Time { return currentTime }),
	)
	defer store.Close()

	// 1. Create entries for user1 and user2
	_, _ = store.TakeToken(ctx, "user1", 5, 1.0)
	_, _ = store.AddAndGetToolCalls(ctx, "user1", ToolCall{Name: "read", Timestamp: currentTime}, 10*time.Second)

	_, _ = store.TakeToken(ctx, "user2", 5, 1.0)
	_, _ = store.AddAndGetToolCalls(ctx, "user2", ToolCall{Name: "write", Timestamp: currentTime}, 10*time.Second)

	if store.BucketCount() != 2 || store.HistoryCount() != 2 {
		t.Fatalf("expected 2 buckets and 2 histories, got %d buckets, %d histories", store.BucketCount(), store.HistoryCount())
	}

	// 2. Advance time by 3 minutes and refresh user1
	currentTime = currentTime.Add(3 * time.Minute)
	_, _ = store.TakeToken(ctx, "user1", 5, 1.0)
	_, _ = store.AddAndGetToolCalls(ctx, "user1", ToolCall{Name: "read2", Timestamp: currentTime}, 10*time.Second)

	// 3. Advance time to 6 minutes from start (user2 is now idle for 6m > 5m TTL, user1 idle for 3m < 5m TTL)
	currentTime = now.Add(6 * time.Minute)

	evicted := store.EvictExpired(currentTime)
	if evicted != 2 {
		t.Fatalf("expected 2 entries evicted (user2 bucket + history), got %d", evicted)
	}

	if store.BucketCount() != 1 || store.HistoryCount() != 1 {
		t.Fatalf("expected 1 active bucket and 1 history remaining, got %d buckets, %d histories", store.BucketCount(), store.HistoryCount())
	}

	// 4. Advance time past user1's TTL (at 9 minutes from start, user1 idle for 6m > 5m TTL)
	currentTime = now.Add(9 * time.Minute)
	evicted = store.EvictExpired(currentTime)
	if evicted != 2 {
		t.Fatalf("expected 2 entries evicted (user1 bucket + history), got %d", evicted)
	}

	if store.BucketCount() != 0 || store.HistoryCount() != 0 {
		t.Fatalf("expected 0 entries left, got %d buckets, %d histories", store.BucketCount(), store.HistoryCount())
	}
}

func TestInMemoryStateStore_BackgroundWorkerTicker(t *testing.T) {
	ctx := context.Background()

	// Short TTL and cleanup interval for quick automated test
	store := NewInMemoryStateStore(
		WithTTL(50*time.Millisecond),
		WithCleanupInterval(25*time.Millisecond),
	)
	defer store.Close()

	_, err := store.TakeToken(ctx, "ephemeral-user", 5, 1.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = store.AddAndGetToolCalls(ctx, "ephemeral-user", ToolCall{Name: "temp", Timestamp: time.Now()}, 10*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.BucketCount() != 1 || store.HistoryCount() != 1 {
		t.Fatalf("expected 1 bucket and 1 history")
	}

	// Wait for TTL + ticker sweep to fire
	time.Sleep(120 * time.Millisecond)

	if store.BucketCount() != 0 || store.HistoryCount() != 0 {
		t.Fatalf("expected background worker to evict idle entries, got %d buckets, %d histories", store.BucketCount(), store.HistoryCount())
	}
}

func TestInMemoryStateStore_BoundedMemoryAndLRUEviction(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	currentTime := now

	const maxKeys = 100
	store := NewInMemoryStateStore(
		WithDisableBackgroundWorker(),
		WithMaxKeys(maxKeys),
		WithTTL(1*time.Hour), // Large TTL so eviction relies on maxKeys LRU
		WithNowFunc(func() time.Time { return currentTime }),
	)
	defer store.Close()

	// Insert 150 unique user keys sequentially
	for i := 0; i < 150; i++ {
		userKey := fmt.Sprintf("user-%03d", i)
		currentTime = currentTime.Add(1 * time.Second) // ensures distinct lastActive timestamps

		allowed, err := store.TakeToken(ctx, userKey, 5, 1.0)
		if err != nil || !allowed {
			t.Fatalf("failed inserting token for %s: %v, allowed=%v", userKey, err, allowed)
		}

		_, err = store.AddAndGetToolCalls(ctx, userKey, ToolCall{Name: "tool", Timestamp: currentTime}, 10*time.Second)
		if err != nil {
			t.Fatalf("failed inserting tool call for %s: %v", userKey, err)
		}

		// Verify that at no point does the store exceed maxKeys
		if store.BucketCount() > maxKeys {
			t.Fatalf("buckets count %d exceeded maxKeys %d at iteration %d", store.BucketCount(), maxKeys, i)
		}
		if store.HistoryCount() > maxKeys {
			t.Fatalf("histories count %d exceeded maxKeys %d at iteration %d", store.HistoryCount(), maxKeys, i)
		}
	}

	// Store size must be exactly maxKeys
	if store.BucketCount() != maxKeys {
		t.Fatalf("expected exactly %d buckets, got %d", maxKeys, store.BucketCount())
	}
	if store.HistoryCount() != maxKeys {
		t.Fatalf("expected exactly %d histories, got %d", maxKeys, store.HistoryCount())
	}

	// The oldest keys (user-000 to user-049) should have been evicted by LRU
	// The newest keys (user-050 to user-149) should still exist
	store.mu.Lock()
	_, oldBucketExists := store.buckets["user-000"]
	_, newBucketExists := store.buckets["user-149"]
	store.mu.Unlock()

	if oldBucketExists {
		t.Fatalf("expected oldest key user-000 to be evicted by LRU")
	}
	if !newBucketExists {
		t.Fatalf("expected newest key user-149 to be present in store")
	}
}

func TestInMemoryStateStore_ConcurrentAccessRace(t *testing.T) {
	ctx := context.Background()

	store := NewInMemoryStateStore(
		WithTTL(100*time.Millisecond),
		WithCleanupInterval(20*time.Millisecond),
		WithMaxKeys(50),
	)
	defer store.Close()

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				userKey := fmt.Sprintf("user-%d", (workerID*10+i)%80)
				_, _ = store.TakeToken(ctx, userKey, 10, 5.0)
				_, _ = store.AddAndGetToolCalls(ctx, userKey, ToolCall{
					Name:      "test_tool",
					ArgsHash:  "args_hash",
					Timestamp: time.Now(),
				}, 5*time.Second)

				if i%20 == 0 {
					store.EvictExpired(time.Now())
				}
			}
		}()
	}

	wg.Wait()
}

func TestInMemoryStateStore_CloseIdempotent(t *testing.T) {
	store := NewInMemoryStateStore(
		WithCleanupInterval(10 * time.Millisecond),
	)

	// First close
	store.Close()

	// Repeated close should not panic or deadlock
	store.Close()
	store.Close()

	// Operations on closed store should safely return
	allowed, err := store.TakeToken(context.Background(), "user", 5, 1.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected allowed=false on closed store")
	}

	calls, err := store.AddAndGetToolCalls(context.Background(), "user", ToolCall{}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != nil {
		t.Fatalf("expected nil calls on closed store")
	}
}

func BenchmarkInMemoryStateStore_TakeToken(b *testing.B) {
	ctx := context.Background()
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.TakeToken(ctx, "bench-user", 1000000, 1000000.0)
	}
}

func BenchmarkInMemoryStateStore_AddAndGetToolCalls(b *testing.B) {
	ctx := context.Background()
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	call := ToolCall{Name: "bench_tool", ArgsHash: "abc", Timestamp: time.Now()}
	window := 10 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.AddAndGetToolCalls(ctx, "bench-user", call, window)
	}
}

