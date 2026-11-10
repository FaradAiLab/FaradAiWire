package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// Store defines the persistence interface for the DuckDB system_settings overlay table.
type Store interface {
	// Migrate executes idempotent DDL to ensure the system_settings table exists.
	Migrate(ctx context.Context) error
	// Get retrieves the stored override string for a key, returning exists=false if not found.
	Get(ctx context.Context, key string) (val string, exists bool, err error)
	// GetAll returns all stored overrides as a key-value map.
	GetAll(ctx context.Context) (map[string]string, error)
	// Set upserts a validated setting override into the system_settings table.
	Set(ctx context.Context, key string, value string) error
	// Delete removes an override from the system_settings table (reverting to baseline default).
	Delete(ctx context.Context, key string) error
}

// DuckDBStore implements the Store interface backed by embedded DuckDB.
type DuckDBStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewDuckDBStore creates a DuckDBStore using an active database connection.
func NewDuckDBStore(db *sql.DB) *DuckDBStore {
	return &DuckDBStore{
		db: db,
	}
}

// Migrate creates the system_settings table idempotently if it does not already exist.
func (s *DuckDBStore) Migrate(ctx context.Context) error {
	if s.db == nil {
		return errors.New("duckdb connection is nil")
	}

	query := `
	CREATE TABLE IF NOT EXISTS system_settings (
		key VARCHAR PRIMARY KEY,
		value VARCHAR NOT NULL,
		category VARCHAR NOT NULL,
		data_type VARCHAR NOT NULL,
		description VARCHAR,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("migrate system_settings table: %w", err)
	}

	return nil
}

// Get retrieves a specific setting override by key.
func (s *DuckDBStore) Get(ctx context.Context, key string) (string, bool, error) {
	if s.db == nil {
		return "", false, errors.New("duckdb connection is nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	query := "SELECT value FROM system_settings WHERE key = ?"
	err := s.db.QueryRowContext(ctx, query, key).Scan(&val)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get setting %q: %w", key, err)
	}

	return val, true, nil
}

// GetAll retrieves all persisted overrides as a key-value map.
func (s *DuckDBStore) GetAll(ctx context.Context) (map[string]string, error) {
	if s.db == nil {
		return nil, errors.New("duckdb connection is nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT key, value FROM system_settings"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query all system_settings: %w", err)
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan system_settings row: %w", err)
		}
		res[k] = v
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system_settings rows: %w", err)
	}

	return res, nil
}

// Set stores or updates a setting override in the system_settings table.
// Validates that the key is registered and the value conforms to schema constraints.
func (s *DuckDBStore) Set(ctx context.Context, key string, value string) error {
	if s.db == nil {
		return errors.New("duckdb connection is nil")
	}

	meta, ok := LookupMeta(key)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownSetting, key)
	}

	// Validate value adheres to bounds before writing
	if _, err := ParseAndValidate(key, value); err != nil {
		return err
	}

	query := `
	INSERT OR REPLACE INTO system_settings (key, value, category, data_type, description, updated_at)
	VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
	`

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, query, key, value, meta.Category, string(meta.Type), meta.Description); err != nil {
		return fmt.Errorf("upsert setting %q: %w", key, err)
	}

	return nil
}

// Delete removes a setting override from the system_settings table, restoring default baseline.
func (s *DuckDBStore) Delete(ctx context.Context, key string) error {
	if s.db == nil {
		return errors.New("duckdb connection is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := "DELETE FROM system_settings WHERE key = ?"
	if _, err := s.db.ExecContext(ctx, query, key); err != nil {
		return fmt.Errorf("delete setting %q: %w", key, err)
	}

	return nil
}
