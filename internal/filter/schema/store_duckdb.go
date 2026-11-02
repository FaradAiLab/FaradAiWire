package schema

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
)

// ErrSchemaNotFound indicates that a requested tool schema record is missing in DuckDB.
var ErrSchemaNotFound = errors.New("tool schema not found")

// ToolSchemaRecord represents an observable and pinned tool schema stored in DuckDB.
type ToolSchemaRecord struct {
	ToolName    string          `json:"tool_name"`
	ProtocolID  string          `json:"protocol_id"`
	SchemaJSON  json.RawMessage `json:"schema_json"`
	SHA256Hash  string          `json:"sha256_hash"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
	IsPinned    bool            `json:"is_pinned"`
}

// Store defines the persistence contract for MCP tool schemas and baseline hashes.
type Store interface {
	Migrate(ctx context.Context) error
	GetSchema(ctx context.Context, toolName string) (*ToolSchemaRecord, error)
	ListSchemas(ctx context.Context) ([]ToolSchemaRecord, error)
	SaveSchema(ctx context.Context, record *ToolSchemaRecord) error
	PinSchema(ctx context.Context, toolName string, pinned bool) error
	Close() error
}

// DuckDBSchemaStore implements Store using embedded DuckDB.
type DuckDBSchemaStore struct {
	db     *sql.DB
	ownsDB bool
	mu     sync.RWMutex
}

// Ensure DuckDBSchemaStore satisfies Store.
var _ Store = (*DuckDBSchemaStore)(nil)

// NewDuckDBSchemaStore creates a Store sharing an existing *sql.DB pool.
// This prevents DuckDB single-process file-lock conflicts when sharing wire.duckdb.
func NewDuckDBSchemaStore(db *sql.DB) *DuckDBSchemaStore {
	return &DuckDBSchemaStore{
		db:     db,
		ownsDB: false,
	}
}

// OpenDuckDBSchemaStore opens a standalone DuckDB connection at dbPath.
func OpenDuckDBSchemaStore(dbPath string) (*DuckDBSchemaStore, error) {
	mgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb at %s: %w", dbPath, err)
	}

	return &DuckDBSchemaStore{
		db:     mgr.DB(),
		ownsDB: true,
	}, nil
}

// Close closes the underlying DuckDB connection if owned.
func (s *DuckDBSchemaStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownsDB && s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// Migrate creates the required mcp_tool_schemas table in DuckDB if it does not exist.
func (s *DuckDBSchemaStore) Migrate(ctx context.Context) error {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return errors.New("duckdb connection is closed")
	}

	query := `
	CREATE TABLE IF NOT EXISTS mcp_tool_schemas (
		tool_name VARCHAR PRIMARY KEY,
		protocol_id VARCHAR,
		schema_json TEXT NOT NULL,
		sha256_hash VARCHAR(64) NOT NULL,
		first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		is_pinned BOOLEAN DEFAULT FALSE
	);
	`
	if _, err := db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to create mcp_tool_schemas table: %w", err)
	}
	return nil
}

// GetSchema retrieves a specific tool schema record by tool name.
func (s *DuckDBSchemaStore) GetSchema(ctx context.Context, toolName string) (*ToolSchemaRecord, error) {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return nil, errors.New("duckdb connection is closed")
	}

	cleanName := strings.TrimSpace(toolName)
	if cleanName == "" {
		return nil, ErrSchemaNotFound
	}

	query := `
		SELECT tool_name, protocol_id, schema_json, sha256_hash, first_seen_at, last_seen_at, is_pinned
		FROM mcp_tool_schemas
		WHERE tool_name = ?
	`
	row := db.QueryRowContext(ctx, query, cleanName)

	var (
		rec        ToolSchemaRecord
		schemaText string
		protoID    sql.NullString
	)

	if err := row.Scan(
		&rec.ToolName,
		&protoID,
		&schemaText,
		&rec.SHA256Hash,
		&rec.FirstSeenAt,
		&rec.LastSeenAt,
		&rec.IsPinned,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSchemaNotFound
		}
		return nil, fmt.Errorf("failed to query schema for tool '%s': %w", cleanName, err)
	}

	if protoID.Valid {
		rec.ProtocolID = protoID.String
	}
	rec.SchemaJSON = json.RawMessage(schemaText)
	return &rec, nil
}

// ListSchemas returns all persisted tool schemas sorted alphabetically by tool name.
func (s *DuckDBSchemaStore) ListSchemas(ctx context.Context) ([]ToolSchemaRecord, error) {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return nil, errors.New("duckdb connection is closed")
	}

	query := `
		SELECT tool_name, protocol_id, schema_json, sha256_hash, first_seen_at, last_seen_at, is_pinned
		FROM mcp_tool_schemas
		ORDER BY tool_name ASC
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list schemas: %w", err)
	}
	defer rows.Close()

	// Preallocate slice for performance (golang-performance)
	records := make([]ToolSchemaRecord, 0, 32)
	for rows.Next() {
		var (
			rec        ToolSchemaRecord
			schemaText string
			protoID    sql.NullString
		)
		if err := rows.Scan(
			&rec.ToolName,
			&protoID,
			&schemaText,
			&rec.SHA256Hash,
			&rec.FirstSeenAt,
			&rec.LastSeenAt,
			&rec.IsPinned,
		); err != nil {
			return nil, fmt.Errorf("failed to scan schema row: %w", err)
		}

		if protoID.Valid {
			rec.ProtocolID = protoID.String
		}
		rec.SchemaJSON = json.RawMessage(schemaText)
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error listing schemas: %w", err)
	}
	return records, nil
}

// SaveSchema persists or updates a tool schema record.
// If the tool is pinned, its baseline schema and hash are preserved against drift.
func (s *DuckDBSchemaStore) SaveSchema(ctx context.Context, record *ToolSchemaRecord) error {
	if record == nil {
		return errors.New("cannot save nil schema record")
	}
	toolName := strings.TrimSpace(record.ToolName)
	if toolName == "" {
		return errors.New("tool_name cannot be empty")
	}

	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return errors.New("duckdb connection is closed")
	}

	now := time.Now().UTC()
	firstSeen := record.FirstSeenAt
	if firstSeen.IsZero() {
		firstSeen = now
	}
	lastSeen := record.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = now
	}

	existing, err := s.GetSchema(ctx, toolName)
	if err != nil && !errors.Is(err, ErrSchemaNotFound) {
		return fmt.Errorf("failed to check existing schema: %w", err)
	}

	if existing == nil {
		insertQuery := `
			INSERT INTO mcp_tool_schemas (tool_name, protocol_id, schema_json, sha256_hash, first_seen_at, last_seen_at, is_pinned)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`
		if _, err := db.ExecContext(ctx, insertQuery, toolName, record.ProtocolID, string(record.SchemaJSON), record.SHA256Hash, firstSeen, lastSeen, record.IsPinned); err != nil {
			return fmt.Errorf("failed to insert schema for tool '%s': %w", toolName, err)
		}
		return nil
	}

	// If pinned, protect baseline: only update last_seen_at (OWASP LLM05 Baseline Pinning)
	if existing.IsPinned {
		updateQuery := `UPDATE mcp_tool_schemas SET last_seen_at = ? WHERE tool_name = ?`
		if _, err := db.ExecContext(ctx, updateQuery, lastSeen, toolName); err != nil {
			return fmt.Errorf("failed to update last_seen_at for pinned tool '%s': %w", toolName, err)
		}
		return nil
	}

	// Not pinned: update schema, hash, protocol_id, and last_seen_at
	updateQuery := `
		UPDATE mcp_tool_schemas
		SET protocol_id = ?, schema_json = ?, sha256_hash = ?, last_seen_at = ?
		WHERE tool_name = ?
	`
	if _, err := db.ExecContext(ctx, updateQuery, record.ProtocolID, string(record.SchemaJSON), record.SHA256Hash, lastSeen, toolName); err != nil {
		return fmt.Errorf("failed to update schema for tool '%s': %w", toolName, err)
	}
	return nil
}

// PinSchema updates the pinning status of a tool schema in DuckDB.
func (s *DuckDBSchemaStore) PinSchema(ctx context.Context, toolName string, pinned bool) error {
	cleanName := strings.TrimSpace(toolName)
	if cleanName == "" {
		return ErrSchemaNotFound
	}

	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return errors.New("duckdb connection is closed")
	}

	query := `UPDATE mcp_tool_schemas SET is_pinned = ? WHERE tool_name = ?`
	res, err := db.ExecContext(ctx, query, pinned, cleanName)
	if err != nil {
		return fmt.Errorf("failed to pin schema for tool '%s': %w", cleanName, err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return ErrSchemaNotFound
	}
	return nil
}
