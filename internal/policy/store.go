package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
)

// DuckDBStore implements the Store interface using embedded DuckDB.
// It can either reuse an existing *sql.DB pool or manage its own connection.
type DuckDBStore struct {
	db      *sql.DB
	ownedDB bool
	mu      sync.RWMutex
}

// NewDuckDBStore creates a Store instance sharing an existing *sql.DB pool.
// This prevents DuckDB single-process file-lock conflicts.
func NewDuckDBStore(db *sql.DB) *DuckDBStore {
	return &DuckDBStore{
		db:      db,
		ownedDB: false,
	}
}

// OpenDuckDBStore opens a standalone DuckDB connection at dbPath.
// Use ":memory:" for in-memory testing.
func OpenDuckDBStore(dbPath string) (*DuckDBStore, error) {
	mgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb at %s: %w", dbPath, err)
	}

	return &DuckDBStore{
		db:      mgr.DB(),
		ownedDB: true,
	}, nil
}

// Close closes the database connection if this store owns it.
func (s *DuckDBStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ownedDB && s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// Migrate creates the required policy governance tables in DuckDB if they do not exist.
func (s *DuckDBStore) Migrate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	schema := `
	CREATE TABLE IF NOT EXISTS dlp_rules (
		id VARCHAR PRIMARY KEY,
		name VARCHAR NOT NULL,
		description VARCHAR DEFAULT '',
		category VARCHAR NOT NULL,
		regex VARCHAR NOT NULL,
		default_action VARCHAR NOT NULL,
		cwe VARCHAR DEFAULT '',
		severity VARCHAR DEFAULT 'MEDIUM',
		is_builtin BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	ALTER TABLE dlp_rules ADD COLUMN IF NOT EXISTS cwe VARCHAR DEFAULT '';
	ALTER TABLE dlp_rules ADD COLUMN IF NOT EXISTS severity VARCHAR DEFAULT 'MEDIUM';

	CREATE TABLE IF NOT EXISTS dlp_packs (
		id VARCHAR PRIMARY KEY,
		name VARCHAR NOT NULL,
		description VARCHAR DEFAULT '',
		category VARCHAR NOT NULL,
		is_builtin BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS dlp_pack_rules (
		pack_id VARCHAR NOT NULL,
		rule_id VARCHAR NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (pack_id, rule_id)
	);

	CREATE TABLE IF NOT EXISTS agent_dlp_configs (
		agent_name VARCHAR PRIMARY KEY,
		pack_ids_json VARCHAR NOT NULL DEFAULT '[]',
		overrides_json VARCHAR NOT NULL DEFAULT '[]',
		custom_patterns_json VARCHAR NOT NULL DEFAULT '[]',
		tool_exemptions_json VARCHAR NOT NULL DEFAULT '{}',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	ALTER TABLE agent_dlp_configs ADD COLUMN IF NOT EXISTS tool_exemptions_json VARCHAR DEFAULT '{}';

	CREATE TABLE IF NOT EXISTS policy_releases (
		version VARCHAR PRIMARY KEY,
		published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		source VARCHAR NOT NULL,
		author VARCHAR,
		changelog TEXT,
		is_active BOOLEAN DEFAULT TRUE
	);
	`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("failed to execute policy schema migration: %w", err)
	}

	return nil
}

// ListRules retrieves DLP rules optionally filtered by category.
func (s *DuckDBStore) ListRules(ctx context.Context, category string) ([]DlpPatternRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	var query string
	var args []any
	if category != "" {
		query = `SELECT id, name, description, category, regex, default_action, cwe, severity, is_builtin, created_at, updated_at
		         FROM dlp_rules WHERE category = ? ORDER BY name ASC`
		args = append(args, category)
	} else {
		query = `SELECT id, name, description, category, regex, default_action, cwe, severity, is_builtin, created_at, updated_at
		         FROM dlp_rules ORDER BY name ASC`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query dlp_rules: %w", err)
	}
	defer rows.Close()

	rules := make([]DlpPatternRule, 0, 16)
	for rows.Next() {
		var r DlpPatternRule
		var act string
		var desc, cwe, sev sql.NullString
		if err := rows.Scan(
			&r.ID, &r.Name, &desc, &r.Category, &r.Regex, &act, &cwe, &sev, &r.IsBuiltin, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan dlp_rule: %w", err)
		}
		if desc.Valid {
			r.Description = desc.String
		}
		if cwe.Valid {
			r.CWE = cwe.String
		}
		if sev.Valid {
			r.Severity = sev.String
		}
		r.DefaultAction = Action(act)
		rules = append(rules, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dlp_rules rows: %w", err)
	}

	return rules, nil
}

// GetRule retrieves a single rule by its unique identifier.
func (s *DuckDBStore) GetRule(ctx context.Context, id string) (*DlpPatternRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT id, name, description, category, regex, default_action, cwe, severity, is_builtin, created_at, updated_at
	          FROM dlp_rules WHERE id = ?`

	var r DlpPatternRule
	var act string
	var desc, cwe, sev sql.NullString
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&r.ID, &r.Name, &desc, &r.Category, &r.Regex, &act, &cwe, &sev, &r.IsBuiltin, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("query dlp_rule %s: %w", id, err)
	}
	if desc.Valid {
		r.Description = desc.String
	}
	if cwe.Valid {
		r.CWE = cwe.String
	}
	if sev.Valid {
		r.Severity = sev.String
	}
	r.DefaultAction = Action(act)
	return &r, nil
}

// CreateRule inserts a new rule into the catalog after validation.
func (s *DuckDBStore) CreateRule(ctx context.Context, rule *DlpPatternRule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	// Check if already exists
	var existingID string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM dlp_rules WHERE id = ?", rule.ID).Scan(&existingID)
	if err == nil {
		return ErrRuleAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check existing rule %s: %w", rule.ID, err)
	}

	now := time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	if rule.Severity == "" {
		rule.Severity = "MEDIUM"
	}

	insertQuery := `
	INSERT INTO dlp_rules (id, name, description, category, regex, default_action, cwe, severity, is_builtin, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = s.db.ExecContext(ctx, insertQuery,
		rule.ID, rule.Name, rule.Description, rule.Category, rule.Regex,
		string(rule.DefaultAction), rule.CWE, rule.Severity, rule.IsBuiltin, rule.CreatedAt, rule.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert dlp_rule %s: %w", rule.ID, err)
	}

	return nil
}

// UpdateRule updates an existing mutable rule. Built-in rules cannot be updated.
func (s *DuckDBStore) UpdateRule(ctx context.Context, rule *DlpPatternRule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	var isBuiltin bool
	err := s.db.QueryRowContext(ctx, "SELECT is_builtin FROM dlp_rules WHERE id = ?", rule.ID).Scan(&isBuiltin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRuleNotFound
		}
		return fmt.Errorf("check rule %s: %w", rule.ID, err)
	}

	if isBuiltin {
		return ErrImmutableBuiltin
	}

	rule.UpdatedAt = time.Now()
	if rule.Severity == "" {
		rule.Severity = "MEDIUM"
	}

	updateQuery := `
	UPDATE dlp_rules
	SET name = ?, description = ?, category = ?, regex = ?, default_action = ?, cwe = ?, severity = ?, updated_at = ?
	WHERE id = ?
	`
	_, err = s.db.ExecContext(ctx, updateQuery,
		rule.Name, rule.Description, rule.Category, rule.Regex,
		string(rule.DefaultAction), rule.CWE, rule.Severity, rule.UpdatedAt, rule.ID,
	)
	if err != nil {
		return fmt.Errorf("update dlp_rule %s: %w", rule.ID, err)
	}

	return nil
}

// DeleteRule removes a non-builtin rule and cleans up its pack associations.
func (s *DuckDBStore) DeleteRule(ctx context.Context, id string) error {
	if err := ValidateIdentifier(id); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	var isBuiltin bool
	err := s.db.QueryRowContext(ctx, "SELECT is_builtin FROM dlp_rules WHERE id = ?", id).Scan(&isBuiltin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRuleNotFound
		}
		return fmt.Errorf("check rule %s: %w", id, err)
	}

	if isBuiltin {
		return ErrImmutableBuiltin
	}

	// Delete from dlp_pack_rules and dlp_rules
	if _, err := s.db.ExecContext(ctx, "DELETE FROM dlp_pack_rules WHERE rule_id = ?", id); err != nil {
		return fmt.Errorf("delete dlp_pack_rules for %s: %w", id, err)
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM dlp_rules WHERE id = ?", id); err != nil {
		return fmt.Errorf("delete dlp_rule %s: %w", id, err)
	}

	return nil
}

// ListPacks returns all policy packs with their associated rule IDs.
func (s *DuckDBStore) ListPacks(ctx context.Context) ([]PolicyPack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT id, name, description, category, is_builtin, created_at, updated_at
	          FROM dlp_packs ORDER BY name ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query dlp_packs: %w", err)
	}
	defer rows.Close()

	packs := make([]PolicyPack, 0, 8)
	for rows.Next() {
		var p PolicyPack
		var desc sql.NullString
		if err := rows.Scan(
			&p.ID, &p.Name, &desc, &p.Category, &p.IsBuiltin, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan dlp_pack: %w", err)
		}
		if desc.Valid {
			p.Description = desc.String
		}
		packs = append(packs, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dlp_packs rows: %w", err)
	}

	// Populate rule IDs for each pack
	for i := range packs {
		ruleIDs, err := s.queryPackRuleIDs(ctx, packs[i].ID)
		if err != nil {
			return nil, err
		}
		packs[i].RuleIDs = ruleIDs
	}

	return packs, nil
}

// GetPack returns a single policy pack with both its rule IDs and populated rules.
func (s *DuckDBStore) GetPack(ctx context.Context, id string) (*PolicyPack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT id, name, description, category, is_builtin, created_at, updated_at
	          FROM dlp_packs WHERE id = ?`

	var p PolicyPack
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&p.ID, &p.Name, &desc, &p.Category, &p.IsBuiltin, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPackNotFound
		}
		return nil, fmt.Errorf("query dlp_pack %s: %w", id, err)
	}
	if desc.Valid {
		p.Description = desc.String
	}

	ruleIDs, err := s.queryPackRuleIDs(ctx, id)
	if err != nil {
		return nil, err
	}
	p.RuleIDs = ruleIDs

	// Populate full rule objects
	if len(ruleIDs) > 0 {
		rulesQuery := `
		SELECT r.id, r.name, r.description, r.category, r.regex, r.default_action, r.cwe, r.severity, r.is_builtin, r.created_at, r.updated_at
		FROM dlp_rules r
		JOIN dlp_pack_rules pr ON r.id = pr.rule_id
		WHERE pr.pack_id = ?
		ORDER BY r.name ASC
		`
		rows, err := s.db.QueryContext(ctx, rulesQuery, id)
		if err != nil {
			return nil, fmt.Errorf("query pack rules for %s: %w", id, err)
		}
		defer rows.Close()

		rules := make([]DlpPatternRule, 0, len(ruleIDs))
		for rows.Next() {
			var r DlpPatternRule
			var act string
			var rDesc, rCWE, rSev sql.NullString
			if err := rows.Scan(
				&r.ID, &r.Name, &rDesc, &r.Category, &r.Regex, &act, &rCWE, &rSev, &r.IsBuiltin, &r.CreatedAt, &r.UpdatedAt,
			); err != nil {
				return nil, fmt.Errorf("scan pack rule: %w", err)
			}
			if rDesc.Valid {
				r.Description = rDesc.String
			}
			if rCWE.Valid {
				r.CWE = rCWE.String
			}
			if rSev.Valid {
				r.Severity = rSev.String
			}
			r.DefaultAction = Action(act)
			rules = append(rules, r)
		}
		p.Rules = rules
	}

	return &p, nil
}

// CreatePack inserts a new pack and associates its rules.
func (s *DuckDBStore) CreatePack(ctx context.Context, pack *PolicyPack) error {
	if err := ValidatePack(pack); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	// Check if pack exists
	var existingID string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM dlp_packs WHERE id = ?", pack.ID).Scan(&existingID)
	if err == nil {
		return ErrPackAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check existing pack %s: %w", pack.ID, err)
	}

	now := time.Now()
	if pack.CreatedAt.IsZero() {
		pack.CreatedAt = now
	}
	pack.UpdatedAt = now

	insertPackQuery := `
	INSERT INTO dlp_packs (id, name, description, category, is_builtin, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	if _, err := s.db.ExecContext(ctx, insertPackQuery,
		pack.ID, pack.Name, pack.Description, pack.Category, pack.IsBuiltin, pack.CreatedAt, pack.UpdatedAt,
	); err != nil {
		return fmt.Errorf("insert dlp_pack %s: %w", pack.ID, err)
	}

	for _, ruleID := range pack.RuleIDs {
		if _, err := s.db.ExecContext(ctx, "INSERT INTO dlp_pack_rules (pack_id, rule_id) VALUES (?, ?)", pack.ID, ruleID); err != nil {
			return fmt.Errorf("associate rule %s to pack %s: %w", ruleID, pack.ID, err)
		}
	}

	return nil
}

// UpdatePack updates pack metadata and its rule associations. Built-in packs cannot be updated.
func (s *DuckDBStore) UpdatePack(ctx context.Context, pack *PolicyPack) error {
	if err := ValidatePack(pack); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	var isBuiltin bool
	err := s.db.QueryRowContext(ctx, "SELECT is_builtin FROM dlp_packs WHERE id = ?", pack.ID).Scan(&isBuiltin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPackNotFound
		}
		return fmt.Errorf("check pack %s: %w", pack.ID, err)
	}

	if isBuiltin {
		return ErrImmutableBuiltin
	}

	pack.UpdatedAt = time.Now()
	updateQuery := `
	UPDATE dlp_packs
	SET name = ?, description = ?, category = ?, updated_at = ?
	WHERE id = ?
	`
	if _, err := s.db.ExecContext(ctx, updateQuery,
		pack.Name, pack.Description, pack.Category, pack.UpdatedAt, pack.ID,
	); err != nil {
		return fmt.Errorf("update dlp_pack %s: %w", pack.ID, err)
	}

	// Re-sync rules
	if _, err := s.db.ExecContext(ctx, "DELETE FROM dlp_pack_rules WHERE pack_id = ?", pack.ID); err != nil {
		return fmt.Errorf("clear pack rules for %s: %w", pack.ID, err)
	}
	for _, ruleID := range pack.RuleIDs {
		if _, err := s.db.ExecContext(ctx, "INSERT INTO dlp_pack_rules (pack_id, rule_id) VALUES (?, ?)", pack.ID, ruleID); err != nil {
			return fmt.Errorf("associate rule %s to pack %s: %w", ruleID, pack.ID, err)
		}
	}

	return nil
}

// DeletePack removes a non-builtin pack and its rule associations.
func (s *DuckDBStore) DeletePack(ctx context.Context, id string) error {
	if err := ValidateIdentifier(id); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	var isBuiltin bool
	err := s.db.QueryRowContext(ctx, "SELECT is_builtin FROM dlp_packs WHERE id = ?", id).Scan(&isBuiltin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPackNotFound
		}
		return fmt.Errorf("check pack %s: %w", id, err)
	}

	if isBuiltin {
		return ErrImmutableBuiltin
	}

	if _, err := s.db.ExecContext(ctx, "DELETE FROM dlp_pack_rules WHERE pack_id = ?", id); err != nil {
		return fmt.Errorf("delete dlp_pack_rules for %s: %w", id, err)
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM dlp_packs WHERE id = ?", id); err != nil {
		return fmt.Errorf("delete dlp_pack %s: %w", id, err)
	}

	return nil
}

// GetAgentConfig retrieves the policy configuration for a named agent.
func (s *DuckDBStore) GetAgentConfig(ctx context.Context, agentName string) (*AgentPolicyConfig, error) {
	if err := ValidateIdentifier(agentName); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `SELECT agent_name, pack_ids_json, overrides_json, custom_patterns_json, tool_exemptions_json, created_at, updated_at
	          FROM agent_dlp_configs WHERE agent_name = ?`

	var cfg AgentPolicyConfig
	var packIDsJSON, overridesJSON, customJSON, toolExemptJSON string
	err := s.db.QueryRowContext(ctx, query, agentName).Scan(
		&cfg.AgentName, &packIDsJSON, &overridesJSON, &customJSON, &toolExemptJSON, &cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("query agent_dlp_configs for %s: %w", agentName, err)
	}

	if err := json.Unmarshal([]byte(packIDsJSON), &cfg.PackIDs); err != nil {
		cfg.PackIDs = []string{}
	}
	if err := json.Unmarshal([]byte(overridesJSON), &cfg.Overrides); err != nil {
		cfg.Overrides = []RuleOverride{}
	}
	if err := json.Unmarshal([]byte(customJSON), &cfg.CustomPatterns); err != nil {
		cfg.CustomPatterns = []CustomPattern{}
	}
	if err := json.Unmarshal([]byte(toolExemptJSON), &cfg.ToolExemptions); err != nil {
		cfg.ToolExemptions = make(map[string]ToolExemption)
	}
	if cfg.ToolExemptions == nil {
		cfg.ToolExemptions = make(map[string]ToolExemption)
	}

	return &cfg, nil
}

// SaveAgentConfig creates or updates an agent's policy configuration.
func (s *DuckDBStore) SaveAgentConfig(ctx context.Context, cfg *AgentPolicyConfig) error {
	if err := ValidateAgentPolicyConfig(cfg); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("database connection is nil")
	}

	packIDsJSON, err := json.Marshal(cfg.PackIDs)
	if err != nil {
		return fmt.Errorf("marshal pack_ids: %w", err)
	}
	overridesJSON, err := json.Marshal(cfg.Overrides)
	if err != nil {
		return fmt.Errorf("marshal overrides: %w", err)
	}
	customJSON, err := json.Marshal(cfg.CustomPatterns)
	if err != nil {
		return fmt.Errorf("marshal custom_patterns: %w", err)
	}
	if cfg.ToolExemptions == nil {
		cfg.ToolExemptions = make(map[string]ToolExemption)
	}
	toolExemptJSON, err := json.Marshal(cfg.ToolExemptions)
	if err != nil {
		return fmt.Errorf("marshal tool_exemptions: %w", err)
	}

	now := time.Now()
	cfg.UpdatedAt = now

	// Check if already exists
	var existing string
	err = s.db.QueryRowContext(ctx, "SELECT agent_name FROM agent_dlp_configs WHERE agent_name = ?", cfg.AgentName).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		cfg.CreatedAt = now
		insertQuery := `
		INSERT INTO agent_dlp_configs (agent_name, pack_ids_json, overrides_json, custom_patterns_json, tool_exemptions_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		`
		_, err = s.db.ExecContext(ctx, insertQuery,
			cfg.AgentName, string(packIDsJSON), string(overridesJSON), string(customJSON), string(toolExemptJSON), cfg.CreatedAt, cfg.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert agent_dlp_configs %s: %w", cfg.AgentName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("check existing agent config %s: %w", cfg.AgentName, err)
	}

	updateQuery := `
	UPDATE agent_dlp_configs
	SET pack_ids_json = ?, overrides_json = ?, custom_patterns_json = ?, tool_exemptions_json = ?, updated_at = ?
	WHERE agent_name = ?
	`
	_, err = s.db.ExecContext(ctx, updateQuery,
		string(packIDsJSON), string(overridesJSON), string(customJSON), string(toolExemptJSON), cfg.UpdatedAt, cfg.AgentName,
	)
	if err != nil {
		return fmt.Errorf("update agent_dlp_configs %s: %w", cfg.AgentName, err)
	}

	return nil
}

// ListAgentsUsingPack lists all agent names whose configuration references the specified pack ID.
func (s *DuckDBStore) ListAgentsUsingPack(ctx context.Context, packID string) ([]string, error) {
	if err := ValidateIdentifier(packID); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("database connection is nil")
	}

	rows, err := s.db.QueryContext(ctx, "SELECT agent_name, pack_ids_json FROM agent_dlp_configs")
	if err != nil {
		return nil, fmt.Errorf("query agent_dlp_configs: %w", err)
	}
	defer rows.Close()

	matchedAgents := make([]string, 0, 4)
	for rows.Next() {
		var agentName, packsJSON string
		if err := rows.Scan(&agentName, &packsJSON); err != nil {
			return nil, fmt.Errorf("scan agent_dlp_configs: %w", err)
		}

		var packIDs []string
		if err := json.Unmarshal([]byte(packsJSON), &packIDs); err == nil {
			for _, id := range packIDs {
				if id == packID {
					matchedAgents = append(matchedAgents, agentName)
					break
				}
			}
		}
	}

	return matchedAgents, nil
}

func (s *DuckDBStore) queryPackRuleIDs(ctx context.Context, packID string) ([]string, error) {
	query := `SELECT rule_id FROM dlp_pack_rules WHERE pack_id = ? ORDER BY rule_id ASC`
	rows, err := s.db.QueryContext(ctx, query, packID)
	if err != nil {
		return nil, fmt.Errorf("query rule_ids for pack %s: %w", packID, err)
	}
	defer rows.Close()

	ruleIDs := make([]string, 0, 8)
	for rows.Next() {
		var rID string
		if err := rows.Scan(&rID); err != nil {
			return nil, fmt.Errorf("scan rule_id: %w", err)
		}
		ruleIDs = append(ruleIDs, rID)
	}

	return ruleIDs, nil
}
