package schema

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func setupTestDuckDBStore(t *testing.T) *DuckDBSchemaStore {
	store, err := OpenDuckDBSchemaStore(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb store: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("failed to migrate duckdb schema store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func TestDuckDBSchemaStore_CRUD_And_Pinning(t *testing.T) {
	store := setupTestDuckDBStore(t)
	ctx := context.Background()

	// 1. Initial Get should return ErrSchemaNotFound
	_, err := store.GetSchema(ctx, "tool_unknown")
	if err != ErrSchemaNotFound {
		t.Fatalf("expected ErrSchemaNotFound, got %v", err)
	}

	// 2. Save new schema
	initialJSON := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`)
	rec := &ToolSchemaRecord{
		ToolName:    "tavily__search",
		ProtocolID:  "tavily",
		SchemaJSON:  initialJSON,
		SHA256Hash:  "hash_v1_123456",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		IsPinned:    false,
	}

	if err := store.SaveSchema(ctx, rec); err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// 3. Query saved schema
	saved, err := store.GetSchema(ctx, "tavily__search")
	if err != nil {
		t.Fatalf("failed to get schema: %v", err)
	}
	if saved.ToolName != "tavily__search" || saved.SHA256Hash != "hash_v1_123456" {
		t.Fatalf("unexpected saved record: %+v", saved)
	}
	if saved.IsPinned {
		t.Fatalf("expected is_pinned to be false initially")
	}

	// 4. Pin schema
	if err := store.PinSchema(ctx, "tavily__search", true); err != nil {
		t.Fatalf("failed to pin schema: %v", err)
	}

	pinnedRec, err := store.GetSchema(ctx, "tavily__search")
	if err != nil || !pinnedRec.IsPinned {
		t.Fatalf("expected tool to be pinned, got: %+v (err: %v)", pinnedRec, err)
	}

	// 5. Attempt schema drift while pinned -> Baseline Pinning Protection!
	driftJSON := json.RawMessage(`{"type":"object","properties":{"evil_payload":{"type":"string"}}}`)
	driftRec := &ToolSchemaRecord{
		ToolName:   "tavily__search",
		ProtocolID: "tavily",
		SchemaJSON: driftJSON,
		SHA256Hash: "hash_v2_poisoned",
		LastSeenAt: time.Now().UTC(),
	}

	if err := store.SaveSchema(ctx, driftRec); err != nil {
		t.Fatalf("save schema returned error: %v", err)
	}

	// The baseline hash and schema MUST remain unchanged because it was pinned
	afterDrift, err := store.GetSchema(ctx, "tavily__search")
	if err != nil {
		t.Fatalf("failed to get schema after drift: %v", err)
	}
	if afterDrift.SHA256Hash != "hash_v1_123456" {
		t.Fatalf("pinned baseline protection failed: expected hash_v1_123456, got %s", afterDrift.SHA256Hash)
	}
	if string(afterDrift.SchemaJSON) != string(initialJSON) {
		t.Fatalf("pinned baseline protection failed: expected initial schema, got %s", string(afterDrift.SchemaJSON))
	}

	// 6. Unpin and update again -> should allow baseline update
	if err := store.PinSchema(ctx, "tavily__search", false); err != nil {
		t.Fatalf("failed to unpin schema: %v", err)
	}

	legitUpdateJSON := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"number"}}}`)
	legitRec := &ToolSchemaRecord{
		ToolName:   "tavily__search",
		ProtocolID: "tavily",
		SchemaJSON: legitUpdateJSON,
		SHA256Hash: "hash_v3_legit",
		LastSeenAt: time.Now().UTC(),
	}
	if err := store.SaveSchema(ctx, legitRec); err != nil {
		t.Fatalf("failed to save legit update: %v", err)
	}

	afterUnpin, err := store.GetSchema(ctx, "tavily__search")
	if err != nil || afterUnpin.SHA256Hash != "hash_v3_legit" {
		t.Fatalf("expected hash to be updated to hash_v3_legit after unpin, got: %+v", afterUnpin)
	}

	// 7. ListSchemas
	list, err := store.ListSchemas(ctx)
	if err != nil {
		t.Fatalf("failed to list schemas: %v", err)
	}
	if len(list) != 1 || list[0].ToolName != "tavily__search" {
		t.Fatalf("unexpected list result: %+v", list)
	}
}

func TestDuckDBSchemaStore_ConcurrentAccess(t *testing.T) {
	store := setupTestDuckDBStore(t)
	ctx := context.Background()

	const workers = 8
	const opsPerWorker = 20

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				toolName := "tool_shared"
				rec := &ToolSchemaRecord{
					ToolName:    toolName,
					ProtocolID:  "proto_shared",
					SchemaJSON:  json.RawMessage(`{"type":"object"}`),
					SHA256Hash:  "shared_hash",
					FirstSeenAt: time.Now().UTC(),
					LastSeenAt:  time.Now().UTC(),
				}
				_ = store.SaveSchema(ctx, rec)
				_, _ = store.GetSchema(ctx, toolName)
				_, _ = store.ListSchemas(ctx)
			}
		}(w)
	}

	wg.Wait()

	rec, err := store.GetSchema(ctx, "tool_shared")
	if err != nil {
		t.Fatalf("expected tool_shared to exist after concurrent ops, got err: %v", err)
	}
	if rec.ToolName != "tool_shared" {
		t.Fatalf("unexpected tool name: %s", rec.ToolName)
	}
}
