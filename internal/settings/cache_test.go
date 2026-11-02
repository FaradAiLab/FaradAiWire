package settings

import (
	"sync"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestCache_GetAndUpdate(t *testing.T) {
	t.Parallel()

	initSettings := DefaultOperationalSettings()
	initSettings.Limits.MaxPayloadBytes = 15 * 1024 * 1024

	cache := NewCache(initSettings)

	// Initial Get
	curr := cache.Get()
	if curr == nil {
		t.Fatal("expected non-nil settings from cache")
	}
	if curr.Limits.MaxPayloadBytes != 15*1024*1024 {
		t.Errorf("expected 15MB, got %d", curr.Limits.MaxPayloadBytes)
	}

	// Update with new pointer
	updated := curr.Clone()
	updated.Limits.MaxPayloadBytes = 30 * 1024 * 1024
	cache.Update(updated)

	curr = cache.Get()
	if curr.Limits.MaxPayloadBytes != 30*1024*1024 {
		t.Errorf("expected 30MB after update, got %d", curr.Limits.MaxPayloadBytes)
	}

	// Update with nil does nothing
	cache.Update(nil)
	curr = cache.Get()
	if curr.Limits.MaxPayloadBytes != 30*1024*1024 {
		t.Errorf("expected 30MB after nil update, got %d", curr.Limits.MaxPayloadBytes)
	}
}

func TestResolveEffectiveSettings(t *testing.T) {
	t.Parallel()

	baseCfg := &config.Config{}
	baseCfg.Filters.HITL.TimeoutSeconds = 45

	overrides := map[string]string{
		"guard.threshold_score":    "0.30",
		"limits.max_payload_bytes": "20971520", // 20MB
		"invalid.corrupted_key":    "xyz",      // Should be ignored
		"timeouts.idle_timeout_sec": "999999",  // Out of bounds, should be ignored
	}

	effective := ResolveEffectiveSettings(baseCfg, overrides)
	if effective == nil {
		t.Fatal("expected non-nil effective settings")
	}

	// Base config applied
	if effective.Guard.HITLTimeoutSec != 45 {
		t.Errorf("expected HITL timeout 45 from base, got %d", effective.Guard.HITLTimeoutSec)
	}

	// DuckDB valid overrides applied
	if effective.Guard.ThresholdScore != 0.30 {
		t.Errorf("expected threshold 0.30 from override, got %v", effective.Guard.ThresholdScore)
	}
	if effective.Limits.MaxPayloadBytes != 20971520 {
		t.Errorf("expected 20MB payload from override, got %d", effective.Limits.MaxPayloadBytes)
	}

	// Unspecified settings retain defaults
	if effective.Timeouts.ToolExecutionTimeoutSec != 60 {
		t.Errorf("expected default 60s tool execution timeout, got %d", effective.Timeouts.ToolExecutionTimeoutSec)
	}
	// Invalid override did not overwrite default
	if effective.Timeouts.IdleTimeoutSec != 90 {
		t.Errorf("expected default 90s idle timeout after out-of-bounds override, got %d", effective.Timeouts.IdleTimeoutSec)
	}
}

func TestCache_Concurrency(t *testing.T) {
	t.Parallel()

	cache := NewCache(nil)
	var wg sync.WaitGroup

	// 50 readers concurrently polling cache
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				s := cache.Get()
				if s == nil {
					t.Errorf("got nil settings")
					return
				}
				_ = s.Limits.MaxPayloadBytes
				_ = s.Guard.ThresholdScore
			}
		}()
	}

	// 10 writers concurrently updating cache
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				curr := cache.Get().Clone()
				curr.Guard.ThresholdScore = 0.10 + float64((idx+j)%8)*0.10
				cache.Update(curr)
			}
		}(i)
	}

	wg.Wait()
}

func BenchmarkCache_Get(b *testing.B) {
	cache := NewCache(DefaultOperationalSettings())
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s := cache.Get()
			if s.Limits.MaxPayloadBytes <= 0 {
				b.Fatal("invalid settings")
			}
		}
	})
}
