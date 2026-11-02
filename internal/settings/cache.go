package settings

import (
	"sync/atomic"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// Cache provides thread-safe, lock-free access to active OperationalSettings via atomic.Pointer.
// This guarantees sub-microsecond in-memory reads on proxy hot-paths, fulfilling the
// Zero-I/O Hot-Path Invariant.
type Cache struct {
	ptr atomic.Pointer[OperationalSettings]
}

// NewCache constructs an atomic settings cache initialized with the provided settings.
func NewCache(initial *OperationalSettings) *Cache {
	if initial == nil {
		initial = DefaultOperationalSettings()
	}
	c := &Cache{}
	c.ptr.Store(initial)
	return c
}

// Get returns the currently active OperationalSettings pointer without lock contention.
// High-performance hot-path calls execute in nanoseconds with zero allocations.
func (c *Cache) Get() *OperationalSettings {
	return c.ptr.Load()
}

// Update atomically exchanges the active operational settings pointer.
func (c *Cache) Update(updated *OperationalSettings) {
	if updated == nil {
		return
	}
	c.ptr.Store(updated)
}

// ResolveEffectiveSettings merges base YAML config defaults with sparse DuckDB overrides.
// Unmodified parameters inherit baseline defaults; sparse DuckDB overrides take precedence.
func ResolveEffectiveSettings(base *config.Config, overrides map[string]string) *OperationalSettings {
	effective := DefaultOperationalSettings()

	// Seed with base YAML config parameters if provided
	if base != nil {
		if base.Filters.HITL.TimeoutSeconds > 0 {
			effective.Guard.HITLTimeoutSec = base.Filters.HITL.TimeoutSeconds
		}
	}

	// Overlay sparse DuckDB overrides
	for key, strVal := range overrides {
		val, err := ParseAndValidate(key, strVal)
		if err != nil {
			// Gracefully skip corrupted, unparseable, or out-of-bounds DB rows
			continue
		}
		_ = ApplySetting(effective, key, val)
	}

	return effective
}
