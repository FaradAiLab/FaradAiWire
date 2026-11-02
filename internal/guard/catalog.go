package guard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
)

var (
	// ErrModelNotFound is returned when a requested guard model does not exist.
	ErrModelNotFound = errors.New("guard model not found")
)

type cachedActiveModel struct {
	model *Model
}

// CatalogStore defines the interface for managing guard models in the persistent catalog.
type CatalogStore interface {
	Migrate(ctx context.Context) error
	Seed(ctx context.Context) error
	List(ctx context.Context) ([]*Model, error)
	Get(ctx context.Context, id string) (*Model, error)
	UpdateStatus(ctx context.Context, id string, status InstallStatus) error
	UpdatePolicy(ctx context.Context, id string, defaultAction ThreatAction, criticalToolsJSON string) error
	UpdateConnection(ctx context.Context, id string, runtimeType string, endpointURL string) error
	UpdateContextWindow(ctx context.Context, id string, contextWindow int) error
	SetActive(ctx context.Context, id string, active bool) error
	GetActive(ctx context.Context) (*Model, error)
	Close() error
}

// Catalog implements CatalogStore backed by embedded DuckDB.
type Catalog struct {
	db          *sql.DB
	ownedDB     bool
	mu          sync.RWMutex
	activeCache atomic.Pointer[cachedActiveModel]
}

// NewCatalog constructs a Catalog using an existing *sql.DB connection.
func NewCatalog(db *sql.DB) *Catalog {
	return &Catalog{
		db:      db,
		ownedDB: false,
	}
}

// OpenCatalog opens or creates an embedded DuckDB database file and returns a Catalog.
func OpenCatalog(dbPath string) (*Catalog, error) {
	mgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb for guard catalog: %w", err)
	}

	return &Catalog{
		db:      mgr.DB(),
		ownedDB: true,
	}, nil
}

// Close closes the database connection if it was opened by OpenCatalog.
func (c *Catalog) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.activeCache.Store(nil)
	if c.ownedDB && c.db != nil {
		err := c.db.Close()
		c.db = nil
		return err
	}
	return nil
}

// Migrate ensures the guard_models table exists with the specified schema.
func (c *Catalog) Migrate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	query := `
	CREATE TABLE IF NOT EXISTS guard_models (
		id VARCHAR PRIMARY KEY,
		name VARCHAR NOT NULL,
		family VARCHAR NOT NULL,
		paradigm VARCHAR DEFAULT 'generative_llm',
		parameter_size VARCHAR NOT NULL,
		ram_required_mb INTEGER NOT NULL,
		disk_size_mb INTEGER NOT NULL,
		description TEXT NOT NULL,
		recommended_for TEXT NOT NULL,
		benchmark_accuracy DOUBLE NOT NULL,
		benchmark_fp_rate DOUBLE NOT NULL,
		benchmark_avg_latency_ms DOUBLE NOT NULL,
		benchmark_p95_latency_ms DOUBLE NOT NULL,
		install_status VARCHAR NOT NULL,
		is_active BOOLEAN DEFAULT FALSE,
		default_action VARCHAR DEFAULT 'hitl',
		critical_tools_json TEXT DEFAULT '[]',
		num_layers INTEGER DEFAULT 32,
		num_kv_heads INTEGER DEFAULT 4,
		head_dim INTEGER DEFAULT 128,
		context_window INTEGER DEFAULT 2048,
		source_url VARCHAR NOT NULL,
		entrypoint_script VARCHAR DEFAULT '',
		ollama_source VARCHAR DEFAULT '',
		docker_image VARCHAR DEFAULT '',
		endpoint_url VARCHAR DEFAULT '',
		runtime_type VARCHAR DEFAULT 'docker',
		installed_at TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS ollama_source VARCHAR DEFAULT '';
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS docker_image VARCHAR DEFAULT '';
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS endpoint_url VARCHAR DEFAULT '';
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS runtime_type VARCHAR DEFAULT 'docker';
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS paradigm VARCHAR DEFAULT 'generative_llm';
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS num_layers INTEGER DEFAULT 32;
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS num_kv_heads INTEGER DEFAULT 4;
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS head_dim INTEGER DEFAULT 128;
	ALTER TABLE guard_models ADD COLUMN IF NOT EXISTS context_window INTEGER DEFAULT 2048;
	`
	_, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to migrate guard_models table: %w", err)
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

// Seed idempotently populates official benchmarked models without overwriting runtime states.
func (c *Catalog) Seed(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	defaultModels := DefaultModels()
	for _, m := range defaultModels {
		// Check if record exists
		var existingID string
		err := c.db.QueryRowContext(ctx, "SELECT id FROM guard_models WHERE id = ?", m.ID).Scan(&existingID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to query existing guard model %s: %w", m.ID, err)
		}

		if errors.Is(err, sql.ErrNoRows) {
			// Insert new record with initial default states
			insertQuery := `
			INSERT INTO guard_models (
				id, name, family, paradigm, parameter_size, ram_required_mb, disk_size_mb,
				description, recommended_for, benchmark_accuracy, benchmark_fp_rate,
				benchmark_avg_latency_ms, benchmark_p95_latency_ms, install_status,
				is_active, default_action, critical_tools_json, source_url,
				entrypoint_script, ollama_source, docker_image,
				num_layers, num_kv_heads, head_dim, context_window, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			`
			_, err = c.db.ExecContext(ctx, insertQuery,
				m.ID, m.Name, m.Family, string(m.Paradigm), m.ParameterSize, m.RAMRequiredMB, m.DiskSizeMB,
				m.Description, m.RecommendedFor, m.BenchmarkAccuracy, m.BenchmarkFPRate,
				m.BenchmarkAvgLatencyMS, m.BenchmarkP95LatencyMS, m.InstallStatus,
				m.IsActive, m.DefaultAction, m.CriticalToolsJSON, m.SourceURL,
				m.EntrypointScript, m.OllamaSource, m.DockerImage,
				m.NumLayers, m.NumKVHeads, m.HeadDim, m.ContextWindow,
			)
			if err != nil {
				return fmt.Errorf("failed to insert guard model %s: %w", m.ID, err)
			}
		} else {
			// Update static metadata without overwriting install_status, is_active, default_action, critical_tools_json, or installed_at
			updateQuery := `
			UPDATE guard_models SET
				name = ?,
				family = ?,
				paradigm = ?,
				parameter_size = ?,
				ram_required_mb = ?,
				disk_size_mb = ?,
				description = ?,
				recommended_for = ?,
				benchmark_accuracy = ?,
				benchmark_fp_rate = ?,
				benchmark_avg_latency_ms = ?,
				benchmark_p95_latency_ms = ?,
				source_url = ?,
				entrypoint_script = ?,
				ollama_source = ?,
				docker_image = ?,
				num_layers = ?,
				num_kv_heads = ?,
				head_dim = ?,
				context_window = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
			`
			_, err = c.db.ExecContext(ctx, updateQuery,
				m.Name, m.Family, string(m.Paradigm), m.ParameterSize, m.RAMRequiredMB, m.DiskSizeMB,
				m.Description, m.RecommendedFor, m.BenchmarkAccuracy, m.BenchmarkFPRate,
				m.BenchmarkAvgLatencyMS, m.BenchmarkP95LatencyMS, m.SourceURL,
				m.EntrypointScript, m.OllamaSource, m.DockerImage,
				m.NumLayers, m.NumKVHeads, m.HeadDim, m.ContextWindow, m.ID,
			)
			if err != nil {
				return fmt.Errorf("failed to update guard model metadata %s: %w", m.ID, err)
			}
		}
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

const modelSelectColumns = `
	id, name, family, paradigm, parameter_size, ram_required_mb, disk_size_mb,
	description, recommended_for, benchmark_accuracy, benchmark_fp_rate,
	benchmark_avg_latency_ms, benchmark_p95_latency_ms, install_status,
	is_active, default_action, critical_tools_json, source_url,
	entrypoint_script, ollama_source, docker_image, endpoint_url, runtime_type, installed_at, updated_at,
	num_layers, num_kv_heads, head_dim, context_window
`

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanModel(s scanner) (*Model, error) {
	var m Model
	var paradigm string
	var installedAt sql.NullTime
	var numLayers, numKVHeads, headDim, contextWindow sql.NullInt64

	if err := s.Scan(
		&m.ID, &m.Name, &m.Family, &paradigm, &m.ParameterSize, &m.RAMRequiredMB, &m.DiskSizeMB,
		&m.Description, &m.RecommendedFor, &m.BenchmarkAccuracy, &m.BenchmarkFPRate,
		&m.BenchmarkAvgLatencyMS, &m.BenchmarkP95LatencyMS, &m.InstallStatus,
		&m.IsActive, &m.DefaultAction, &m.CriticalToolsJSON, &m.SourceURL,
		&m.EntrypointScript, &m.OllamaSource, &m.DockerImage, &m.EndpointURL, &m.RuntimeType, &installedAt, &m.UpdatedAt,
		&numLayers, &numKVHeads, &headDim, &contextWindow,
	); err != nil {
		return nil, err
	}

	if paradigm == string(ModelParadigmDecisionModel) {
		m.Paradigm = ModelParadigmDecisionModel
	} else {
		m.Paradigm = ModelParadigmGenerativeLLM
	}

	if installedAt.Valid {
		m.InstalledAt = &installedAt.Time
	}

	m.NumLayers = int(numLayers.Int64)
	if m.NumLayers <= 0 {
		m.NumLayers = 32
	}
	m.NumKVHeads = int(numKVHeads.Int64)
	if m.NumKVHeads <= 0 {
		m.NumKVHeads = 4
	}
	m.HeadDim = int(headDim.Int64)
	if m.HeadDim <= 0 {
		m.HeadDim = 128
	}
	m.ContextWindow = int(contextWindow.Int64)
	if m.ContextWindow <= 0 {
		m.ContextWindow = 2048
	}

	m.ParsedCriticalTools = m.GetCriticalTools()
	return &m, nil
}

// List returns all models currently registered in the catalog ordered by ID.
func (c *Catalog) List(ctx context.Context) ([]*Model, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT ` + modelSelectColumns + ` FROM guard_models ORDER BY id ASC`
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query guard models: %w", err)
	}
	defer rows.Close()

	var models []*Model
	for rows.Next() {
		m, err := scanModel(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan guard model row: %w", err)
		}
		models = append(models, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("guard models rows iteration error: %w", err)
	}

	return models, nil
}

// Get returns a single model by ID.
func (c *Catalog) Get(ctx context.Context, id string) (*Model, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT ` + modelSelectColumns + ` FROM guard_models WHERE id = ?`
	row := c.db.QueryRowContext(ctx, query, id)
	m, err := scanModel(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrModelNotFound
		}
		return nil, fmt.Errorf("failed to query guard model %s: %w", id, err)
	}
	return m, nil
}

// UpdateStatus updates the installation status of a model.
func (c *Catalog) UpdateStatus(ctx context.Context, id string, status InstallStatus) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	var res sql.Result
	var err error

	if status == InstallStatusInstalled {
		query := `
		UPDATE guard_models
		SET install_status = ?, installed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
		`
		res, err = c.db.ExecContext(ctx, query, string(status), id)
	} else {
		query := `
		UPDATE guard_models
		SET install_status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
		`
		res, err = c.db.ExecContext(ctx, query, string(status), id)
	}

	if err != nil {
		return fmt.Errorf("failed to update guard model status for %s: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return ErrModelNotFound
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

// UpdatePolicy updates the threat enforcement action policy and critical tool overrides for a model.
func (c *Catalog) UpdatePolicy(ctx context.Context, id string, defaultAction ThreatAction, criticalToolsJSON string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	if defaultAction != ThreatActionHITL && defaultAction != ThreatActionBlock {
		defaultAction = ThreatActionHITL
	}
	if criticalToolsJSON == "" {
		criticalToolsJSON = "[]"
	}

	query := `
	UPDATE guard_models
	SET default_action = ?, critical_tools_json = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`
	res, err := c.db.ExecContext(ctx, query, string(defaultAction), criticalToolsJSON, id)
	if err != nil {
		return fmt.Errorf("failed to update guard model policy for %s: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return ErrModelNotFound
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

// SetActive sets a model's active state, enforcing the single-active-model invariant.
func (c *Catalog) SetActive(ctx context.Context, id string, active bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	// Verify model exists first
	var exists bool
	err := c.db.QueryRowContext(ctx, "SELECT count(*) > 0 FROM guard_models WHERE id = ?", id).Scan(&exists)
	if err != nil || !exists {
		return ErrModelNotFound
	}

	if active {
		// Deactivate all models first to guarantee single-active-model invariant
		if _, err := c.db.ExecContext(ctx, "UPDATE guard_models SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP"); err != nil {
			return fmt.Errorf("failed to reset active guard models: %w", err)
		}
		// Activate the requested model
		query := "UPDATE guard_models SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
		if _, err := c.db.ExecContext(ctx, query, id); err != nil {
			return fmt.Errorf("failed to activate guard model %s: %w", id, err)
		}
	} else {
		query := "UPDATE guard_models SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
		if _, err := c.db.ExecContext(ctx, query, id); err != nil {
			return fmt.Errorf("failed to deactivate guard model %s: %w", id, err)
		}
	}

	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

func (c *Catalog) refreshActiveCacheLocked(ctx context.Context) error {
	if c.db == nil {
		c.activeCache.Store(&cachedActiveModel{model: nil})
		return errors.New("database connection is nil")
	}

	query := `SELECT ` + modelSelectColumns + ` FROM guard_models WHERE is_active = TRUE LIMIT 1`
	row := c.db.QueryRowContext(ctx, query)
	m, err := scanModel(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.activeCache.Store(&cachedActiveModel{model: nil})
			return nil
		}
		return fmt.Errorf("failed to query active guard model: %w", err)
	}

	c.activeCache.Store(&cachedActiveModel{model: m})
	return nil
}

// GetActive returns the currently active guard model, or nil if no model is active.
// Thread-safe and zero-I/O: reads from the in-memory cache populated during startup and mutations.
func (c *Catalog) GetActive(ctx context.Context) (*Model, error) {
	cached := c.activeCache.Load()
	if cached == nil {
		c.mu.Lock()
		cached = c.activeCache.Load()
		if cached == nil {
			if err := c.refreshActiveCacheLocked(ctx); err != nil {
				c.mu.Unlock()
				return nil, err
			}
			cached = c.activeCache.Load()
		}
		c.mu.Unlock()
	}

	if cached == nil || cached.model == nil {
		return nil, nil
	}

	clone := *cached.model
	return &clone, nil
}

// UpdateConnection updates the connection endpoint URL and runtime type for a model.
func (c *Catalog) UpdateConnection(ctx context.Context, id string, runtimeType string, endpointURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	if runtimeType == "" {
		runtimeType = "docker"
	}

	query := `
	UPDATE guard_models
	SET endpoint_url = ?, runtime_type = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`
	res, err := c.db.ExecContext(ctx, query, endpointURL, runtimeType, id)
	if err != nil {
		return fmt.Errorf("failed to update guard model connection for %s: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return ErrModelNotFound
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

// UpdateContextWindow updates the connection-time pinned context window for a model.
func (c *Catalog) UpdateContextWindow(ctx context.Context, id string, contextWindow int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.db == nil {
		return errors.New("database connection is nil")
	}

	if contextWindow <= 0 {
		contextWindow = 2048
	}

	query := `
	UPDATE guard_models
	SET context_window = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`
	res, err := c.db.ExecContext(ctx, query, contextWindow, id)
	if err != nil {
		return fmt.Errorf("failed to update guard model context window for %s: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return ErrModelNotFound
	}
	_ = c.refreshActiveCacheLocked(ctx)
	return nil
}

