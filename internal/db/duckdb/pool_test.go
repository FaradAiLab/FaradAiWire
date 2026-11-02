package duckdb

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestManager_MemoryInstance(t *testing.T) {
	mgr, err := NewManager(Config{DBPath: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create memory DuckDB manager: %v", err)
	}
	defer mgr.Close()

	db := mgr.DB()
	if db == nil {
		t.Fatal("expected non-nil *sql.DB")
	}

	// Simple query verification
	var result int
	if err := db.QueryRow("SELECT 42").Scan(&result); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if result != 42 {
		t.Fatalf("expected 42, got %d", result)
	}
}

func TestManager_FileInstance_And_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_wire.duckdb")

	mgr, err := NewManager(Config{
		DBPath:       dbPath,
		MaxOpenConns: 4,
		MaxIdleConns: 4,
	})
	if err != nil {
		t.Fatalf("failed to create file DuckDB manager: %v", err)
	}
	defer mgr.Close()

	db := mgr.DB()

	// Create test table
	_, err = db.Exec("CREATE TABLE test_counter (id INT, val VARCHAR);")
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	// Concurrent writes and reads
	var wg sync.WaitGroup
	workers := 10
	iterations := 20

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, err := db.Exec("INSERT INTO test_counter VALUES (?, ?);", workerID*iterations+i, "data")
				if err != nil {
					t.Errorf("worker %d failed insert: %v", workerID, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	var count int
	if err := db.QueryRow("SELECT count(*) FROM test_counter;").Scan(&count); err != nil {
		t.Fatalf("failed to count rows: %v", err)
	}
	if count != workers*iterations {
		t.Fatalf("expected %d rows, got %d", workers*iterations, count)
	}
}

func TestManager_Close_Idempotent(t *testing.T) {
	mgr, err := NewManager(Config{DBPath: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	// Second close should be a no-op and return nil
	if err := mgr.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}

	if mgr.DB() != nil {
		t.Fatal("expected DB() to return nil after Close()")
	}
}
