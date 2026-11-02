package duckdb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/marcboeker/go-duckdb"
)

// DefaultMaxOpenConns defines the standard concurrent connection ceiling for embedded DuckDB.
const DefaultMaxOpenConns = 4

// DefaultMaxIdleConns defines the standard idle connection pool capacity.
const DefaultMaxIdleConns = 4

// Config defines connection pool configuration for DuckDB.
type Config struct {
	DBPath       string
	MaxOpenConns int
	MaxIdleConns int
}

// Manager manages a thread-safe connection pool to an embedded DuckDB database file or in-memory instance.
// Because DuckDB is an embedded database enforcing single-process file locking, this manager guarantees
// a single shared *sql.DB pool with coordinated connection limits to eliminate lock contention across
// telemetry, policy governance, guard catalog, and schema stores.
type Manager struct {
	dbPath string
	db     *sql.DB
	mu     sync.RWMutex
	closed bool
}

// NewManager opens or initializes a shared DuckDB connection pool.
func NewManager(cfg Config) (*Manager, error) {
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = DefaultMaxOpenConns
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = DefaultMaxIdleConns
	}

	dsn := cfg.DBPath
	if dsn == "" {
		dsn = ":memory:"
	}

	if dsn != ":memory:" && !strings.HasPrefix(dsn, "?") {
		dir := filepath.Dir(dsn)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create duckdb directory %q: %w", dir, err)
		}
	}

	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb connection at %q: %w", dsn, err)
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(0)

	// Verify connectivity
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping duckdb at %q: %w", dsn, err)
	}

	return &Manager{
		dbPath: dsn,
		db:     db,
	}, nil
}

// DB returns the underlying shared *sql.DB connection pool.
func (m *Manager) DB() *sql.DB {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.db
}

// DBPath returns the configured path or DSN of the database.
func (m *Manager) DBPath() string {
	return m.dbPath
}

// Close gracefully closes the underlying connection pool.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed || m.db == nil {
		return nil
	}
	m.closed = true
	err := m.db.Close()
	m.db = nil
	return err
}
