package settings

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	_ "github.com/marcboeker/go-duckdb"
)

func setupTestStore(t *testing.T) (*DuckDBStore, *sql.DB) {
	t.Helper()
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb: %v", err)
	}

	store := NewDuckDBStore(db)
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("failed to migrate system_settings: %v", err)
	}

	return store, db
}

func TestDuckDBStore_MigrateIdempotency(t *testing.T) {
	t.Parallel()

	store, db := setupTestStore(t)
	defer db.Close()

	ctx := context.Background()
	// Run migration a second time to ensure idempotency
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second migration call failed: %v", err)
	}
}

func TestDuckDBStore_CRUD(t *testing.T) {
	t.Parallel()

	store, db := setupTestStore(t)
	defer db.Close()

	ctx := context.Background()

	// 1. Initial Get on non-existent key returns exists=false
	val, exists, err := store.Get(ctx, "guard.threshold_score")
	if err != nil {
		t.Fatalf("unexpected error getting setting: %v", err)
	}
	if exists || val != "" {
		t.Errorf("expected exists=false, got exists=%v, val=%q", exists, val)
	}

	// 2. Set valid setting
	if err := store.Set(ctx, "guard.threshold_score", "0.35"); err != nil {
		t.Fatalf("failed to set setting: %v", err)
	}

	// 3. Get setting
	val, exists, err = store.Get(ctx, "guard.threshold_score")
	if err != nil {
		t.Fatalf("unexpected error getting setting: %v", err)
	}
	if !exists || val != "0.35" {
		t.Errorf("expected exists=true, val='0.35', got exists=%v, val=%q", exists, val)
	}

	// 4. Update setting (upsert)
	if err := store.Set(ctx, "guard.threshold_score", "0.75"); err != nil {
		t.Fatalf("failed to update setting: %v", err)
	}
	val, exists, err = store.Get(ctx, "guard.threshold_score")
	if err != nil {
		t.Fatalf("unexpected error getting setting: %v", err)
	}
	if !exists || val != "0.75" {
		t.Errorf("expected exists=true, val='0.75', got exists=%v, val=%q", exists, val)
	}

	// 5. GetAll
	if err := store.Set(ctx, "limits.max_payload_bytes", "20971520"); err != nil {
		t.Fatalf("failed to set second setting: %v", err)
	}
	all, err := store.GetAll(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting all settings: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 settings in GetAll, got %d", len(all))
	}
	if all["guard.threshold_score"] != "0.75" || all["limits.max_payload_bytes"] != "20971520" {
		t.Errorf("unexpected GetAll content: %v", all)
	}

	// 6. Delete (revert to baseline)
	if err := store.Delete(ctx, "guard.threshold_score"); err != nil {
		t.Fatalf("failed to delete setting: %v", err)
	}
	val, exists, err = store.Get(ctx, "guard.threshold_score")
	if err != nil {
		t.Fatalf("unexpected error getting setting: %v", err)
	}
	if exists {
		t.Errorf("expected exists=false after delete, got %v", val)
	}
}

func TestDuckDBStore_ValidationFailure(t *testing.T) {
	t.Parallel()

	store, db := setupTestStore(t)
	defer db.Close()

	ctx := context.Background()

	// 1. Unknown key
	err := store.Set(ctx, "invalid.unknown_key", "123")
	if !errors.Is(err, ErrUnknownSetting) {
		t.Errorf("expected ErrUnknownSetting, got %v", err)
	}

	// 2. Out of bounds value
	err = store.Set(ctx, "limits.max_payload_bytes", "500") // min is 1024
	if !errors.Is(err, ErrInvalidValue) {
		t.Errorf("expected ErrInvalidValue for out-of-bounds, got %v", err)
	}

	// 3. Malformed string
	err = store.Set(ctx, "guard.threshold_score", "not_a_float")
	if !errors.Is(err, ErrInvalidValue) {
		t.Errorf("expected ErrInvalidValue for unparseable float, got %v", err)
	}
}

func TestDuckDBStore_Concurrency(t *testing.T) {
	t.Parallel()

	store, db := setupTestStore(t)
	defer db.Close()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrently write and read multiple keys
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			score := 0.10 + float64(idx%8)*0.10
			_ = store.Set(ctx, "guard.threshold_score", string(rune(idx)))
			_ = store.Set(ctx, "timeouts.tool_execution_sec", "120")
			_ = score
		}(i)

		go func() {
			defer wg.Done()
			_, _, _ = store.Get(ctx, "guard.threshold_score")
			_, _ = store.GetAll(ctx)
		}()
	}

	wg.Wait()
}

func TestDuckDBStore_NilDB(t *testing.T) {
	t.Parallel()

	nilStore := NewDuckDBStore(nil)
	ctx := context.Background()

	if err := nilStore.Migrate(ctx); err == nil {
		t.Error("expected error on Migrate with nil DB")
	}
	if _, _, err := nilStore.Get(ctx, "key"); err == nil {
		t.Error("expected error on Get with nil DB")
	}
	if _, err := nilStore.GetAll(ctx); err == nil {
		t.Error("expected error on GetAll with nil DB")
	}
	if err := nilStore.Set(ctx, "key", "val"); err == nil {
		t.Error("expected error on Set with nil DB")
	}
	if err := nilStore.Delete(ctx, "key"); err == nil {
		t.Error("expected error on Delete with nil DB")
	}
}
