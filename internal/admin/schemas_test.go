package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
)

func setupTestAdminServerWithSchemaStore(t *testing.T) (*AdminServer, schema.Store) {
	store, err := schema.OpenDuckDBSchemaStore(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb schema store: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("failed to migrate duckdb schema store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	server := NewAdminServer(nil, func() error { return nil }, func() {})
	server.SetSchemaStore(store)
	return server, store
}

func TestAdminEndpoints_Schemas_CRUD_And_Pinning(t *testing.T) {
	server, store := setupTestAdminServerWithSchemaStore(t)
	handler := server.Handler()
	ctx := context.Background()

	// 1. GET /admin/schemas initially returns empty array
	req := httptest.NewRequest(http.MethodGet, "/admin/schemas", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Schemas []schema.ToolSchemaRecord `json:"schemas"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode schemas response: %v", err)
	}
	if len(listResp.Schemas) != 0 {
		t.Fatalf("expected 0 schemas initially, got %d", len(listResp.Schemas))
	}

	// 2. Seed a tool schema record directly into DuckDB store
	rec1 := &schema.ToolSchemaRecord{
		ToolName:    "tavily__search",
		ProtocolID:  "tavily",
		SchemaJSON:  json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
		SHA256Hash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		IsPinned:    false,
	}
	if err := store.SaveSchema(ctx, rec1); err != nil {
		t.Fatalf("failed to seed schema: %v", err)
	}

	// 3. GET /admin/schemas returns the seeded schema
	req = httptest.NewRequest(http.MethodGet, "/admin/schemas", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode schemas response: %v", err)
	}
	if len(listResp.Schemas) != 1 || listResp.Schemas[0].ToolName != "tavily__search" {
		t.Fatalf("unexpected schemas list: %+v", listResp.Schemas)
	}

	// 4. GET /admin/schemas/tavily__search returns individual record
	req = httptest.NewRequest(http.MethodGet, "/admin/schemas/tavily__search", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var singleRec schema.ToolSchemaRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &singleRec); err != nil {
		t.Fatalf("failed to decode single schema: %v", err)
	}
	if singleRec.ToolName != "tavily__search" || singleRec.IsPinned {
		t.Fatalf("unexpected schema record: %+v", singleRec)
	}

	// 5. POST /admin/schemas/tavily__search/pin toggles pinning to true
	pinPayload := map[string]bool{"pinned": true}
	body, _ := json.Marshal(pinPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/schemas/tavily__search/pin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on pin, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify pinning took effect in store
	pinnedRec, err := store.GetSchema(ctx, "tavily__search")
	if err != nil || !pinnedRec.IsPinned {
		t.Fatalf("expected tool to be pinned in DuckDB, got: %+v (err: %v)", pinnedRec, err)
	}

	// 6. Security path traversal protection (golang-security)
	req = httptest.NewRequest(http.MethodGet, "/admin/schemas/..%2F..%2Fetc%2Fpasswd", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
		t.Fatalf("expected 400 or 404 on path traversal attempt, got %d", rec.Code)
	}
}
