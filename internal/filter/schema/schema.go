package schema

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/xeipuuv/gojsonschema"
)

// Ensure SchemaFilter implements filter.SecurityFilter, filter.RequestFilter, and filter.ResponseFilter.
var (
	_ filter.SecurityFilter = (*SchemaFilter)(nil)
	_ filter.RequestFilter  = (*SchemaFilter)(nil)
	_ filter.ResponseFilter = (*SchemaFilter)(nil)
)

type schemaWriteTask struct {
	relPath    string
	data       []byte
	toolRecord *ToolSchemaRecord
	done       chan struct{}
}

// SchemaFilter implements parameter schema validation and baseline drift protection.
type SchemaFilter struct {
	enabled         bool
	schemasDir      string // Optional directory for static pre-configured schemas
	dynamicCapture  bool   // Capture schemas dynamically from tools/list response
	baselinePinning bool   // Pin first-seen tool schemas and update on changes

	schemaCache      map[string]json.RawMessage // tool_name -> raw JSON schema
	schemaCacheLower map[string]json.RawMessage // strings.ToLower(tool_name) -> raw JSON schema
	schemaBaselines  map[string]string          // tool_name -> sha256 hex string
	duckdbStore      Store                      // Optional persistent DuckDB storage
	mu               sync.RWMutex

	writeChan chan schemaWriteTask
	doneChan  chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	isClosed  atomic.Bool
}

// SetDuckDBStore configures the DuckDB persistence store for tool schemas.
func (s *SchemaFilter) SetDuckDBStore(store Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.duckdbStore = store
}

// GetDuckDBStore returns the configured DuckDB persistence store.
func (s *SchemaFilter) GetDuckDBStore() Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.duckdbStore
}

// NewSchemaFilter creates a new SchemaFilter instance.
func NewSchemaFilter(enabled bool, schemasDir string, dynamicCapture bool, baselinePinning bool) *SchemaFilter {
	f := &SchemaFilter{
		enabled:          enabled,
		schemasDir:       schemasDir,
		dynamicCapture:   dynamicCapture,
		baselinePinning:  baselinePinning,
		schemaCache:      make(map[string]json.RawMessage),
		schemaCacheLower: make(map[string]json.RawMessage),
		schemaBaselines:  make(map[string]string),
		writeChan:        make(chan schemaWriteTask, 512),
		doneChan:         make(chan struct{}),
	}

	// Start asynchronous write-behind background worker
	f.wg.Add(1)
	go f.writeLoop()

	if enabled && schemasDir != "" {
		if err := f.LoadSchemasFromDisk(); err != nil {
			slog.Warn("Failed to load initial schemas from disk", slog.String("schemas_dir", schemasDir), slog.String("error", err.Error()))
		}
	}

	return f
}

// Name returns the identifier of the filter.
func (s *SchemaFilter) Name() string {
	return "schema_validation"
}

// Order returns the pipeline execution precedence (OrderSchemaValidation = 30).
func (s *SchemaFilter) Order() int {
	return filter.OrderSchemaValidation
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (s *SchemaFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := s.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (s *SchemaFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	res, err := s.FilterResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Flush blocks until all queued write-behind tasks have been written to disk or the context expires.
// Concurrent calls during or after shutdown return immediately without deadlocking.
func (s *SchemaFilter) Flush(ctxs ...context.Context) error {
	if s == nil || s.isClosed.Load() {
		return nil
	}

	var ctx context.Context
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	} else {
		ctx = context.Background()
	}

	select {
	case <-s.doneChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	done := make(chan struct{})
	task := schemaWriteTask{done: done}

	select {
	case <-s.doneChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case s.writeChan <- task:
	}

	select {
	case <-s.doneChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// FlushWithContext is a convenience wrapper for Flush with an explicit context.
func (s *SchemaFilter) FlushWithContext(ctx context.Context) error {
	return s.Flush(ctx)
}

// Close gracefully terminates the write-behind background worker and drains remaining writes.
func (s *SchemaFilter) Close() error {
	s.closeOnce.Do(func() {
		s.isClosed.Store(true)
		close(s.doneChan)
		s.wg.Wait()
	})
	return nil
}

func (s *SchemaFilter) writeLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.doneChan:
			// Drain remaining tasks before stopping
			for {
				select {
				case task := <-s.writeChan:
					s.persistTask(task)
				default:
					return
				}
			}
		case task := <-s.writeChan:
			s.persistTask(task)
		}
	}
}

func (s *SchemaFilter) persistTask(task schemaWriteTask) {
	defer func() {
		if task.done != nil {
			close(task.done)
		}
	}()

	if task.toolRecord != nil {
		s.mu.RLock()
		store := s.duckdbStore
		s.mu.RUnlock()
		if store != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := store.SaveSchema(ctx, task.toolRecord); err != nil {
				slog.Warn("Failed to persist schema to DuckDB", slog.String("tool", task.toolRecord.ToolName), slog.String("error", err.Error()))
			}
			cancel()
		}
	}

	if task.relPath == "" || len(task.data) == 0 || s.schemasDir == "" {
		return
	}

	if err := os.MkdirAll(s.schemasDir, 0750); err != nil {
		slog.Error("Failed to create schemas directory", slog.String("dir", s.schemasDir), slog.String("error", err.Error()))
		return
	}

	filePath, err := pathguard.ResolveSandboxedPath(s.schemasDir, task.relPath)
	if err != nil {
		slog.Error("Sandboxed path resolution failed for schema", slog.String("path", task.relPath), slog.String("error", err.Error()))
		return
	}

	if err := os.WriteFile(filePath, task.data, 0644); err != nil {
		slog.Error("Failed to write schema file on disk", slog.String("path", task.relPath), slog.String("error", err.Error()))
	}
}

// LoadSchemasFromDisk reads all cached tool schemas from disk.
func (s *SchemaFilter) LoadSchemasFromDisk() error {
	if s.schemasDir == "" {
		return nil
	}

	// Ensure directory exists with restricted permissions
	if err := os.MkdirAll(s.schemasDir, 0750); err != nil {
		return err
	}

	files, err := os.ReadDir(s.schemasDir)
	if err != nil {
		return err
	}

	loadedCache := make(map[string]json.RawMessage)
	loadedBaselines := make(map[string]string)

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") && file.Name() != "mcp_tools.json" {
			toolName := strings.TrimSuffix(file.Name(), ".json")
			filePath, pErr := pathguard.ResolveSandboxedPath(s.schemasDir, file.Name())
			if pErr != nil {
				continue
			}
			content, err := os.ReadFile(filePath)
			if err != nil {
				slog.Error("Failed to read schema file", slog.String("path", filePath), slog.String("error", err.Error()))
				continue
			}

			normalized, err := NormalizeJSON(content)
			if err != nil {
				slog.Error("Failed to normalize schema", slog.String("tool", toolName), slog.String("error", err.Error()))
				continue
			}

			hash := sha256.Sum256(normalized)
			hashStr := hex.EncodeToString(hash[:])

			loadedCache[toolName] = content
			loadedBaselines[toolName] = hashStr
			slog.Debug("Loaded stored schema baseline for tool", slog.String("tool", toolName), slog.String("hash", hashStr))
		}
	}

	s.mu.Lock()
	for k, v := range loadedCache {
		s.schemaCache[k] = v
		s.schemaCacheLower[strings.ToLower(k)] = v
	}
	for k, v := range loadedBaselines {
		s.schemaBaselines[k] = v
	}
	s.mu.Unlock()

	return nil
}

// FilterRequest validates tool arguments against the cached JSON Schema on tools/call requests.
func (s *SchemaFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if !s.enabled {
		return req, nil
	}

	if req.Method != "tools/call" {
		return req, nil
	}

	// Parse tool name and arguments
	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return nil, mcp.NewError(mcp.ErrInvalidParams, "Failed to parse tool call params: "+err.Error(), nil)
	}

	s.mu.RLock()
	schemaRaw, exists := s.schemaCache[callParams.Name]
	if !exists && callParams.Name != "" {
		schemaRaw, exists = s.schemaCacheLower[strings.ToLower(callParams.Name)]
	}
	s.mu.RUnlock()

	if !exists {
		slog.WarnContext(ctx, "No JSON Schema cached for tool, skipping validation", slog.String("tool", callParams.Name))
		return req, nil
	}

	// Validate arguments against schema
	schemaLoader := gojsonschema.NewStringLoader(string(schemaRaw))

	// Default to empty object if no arguments are passed
	argsStr := string(callParams.Arguments)
	if argsStr == "" || argsStr == "null" {
		argsStr = "{}"
	}
	documentLoader := gojsonschema.NewStringLoader(argsStr)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, mcp.NewError(mcp.ErrSchemaValidation, "JSON Schema validation engine error: "+err.Error(), nil)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return nil, mcp.NewError(mcp.ErrSchemaValidation, fmt.Sprintf("Tool arguments validation failed: %v", errors), map[string]interface{}{
			"errors": errors,
			"tool":   callParams.Name,
		})
	}

	return req, nil
}

type mcpToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type toolsListResponse struct {
	Tools []mcpToolDefinition `json:"tools"`
}

type preparedTool struct {
	name        string
	inputSchema json.RawMessage
	hashStr     string
}

// FilterResponse captures schemas, compares signatures, and offloads baseline file updates to the write-behind worker.
func (s *SchemaFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	if !s.enabled || resp.Result == nil {
		return resp, nil
	}

	// Try to unmarshal to see if it is a tools/list response
	var listResp toolsListResponse
	if err := json.Unmarshal(resp.Result, &listResp); err != nil || len(listResp.Tools) == 0 {
		return resp, nil
	}

	// Pre-process normalization and SHA-256 hash calculations OUTSIDE mutex lock
	prepared := make([]preparedTool, 0, len(listResp.Tools))
	for _, tool := range listResp.Tools {
		normalizedSchema, err := normalizeJSON(tool.InputSchema)
		if err != nil {
			slog.ErrorContext(ctx, "Error normalizing schema for tool", slog.String("tool", tool.Name), slog.String("error", err.Error()))
			continue
		}
		hash := sha256.Sum256(normalizedSchema)
		prepared = append(prepared, preparedTool{
			name:        tool.Name,
			inputSchema: tool.InputSchema,
			hashStr:     hex.EncodeToString(hash[:]),
		})
	}

	var writeTasks []schemaWriteTask

	// Acquire mutex strictly for in-memory cache/baseline updates
	s.mu.Lock()
	for _, pt := range prepared {
		var protoID string
		if strings.Contains(pt.name, "__") {
			parts := strings.SplitN(pt.name, "__", 2)
			protoID = parts[0]
		}
		toolRec := &ToolSchemaRecord{
			ToolName:    pt.name,
			ProtocolID:  protoID,
			SchemaJSON:  pt.inputSchema,
			SHA256Hash:  pt.hashStr,
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		}

		if s.baselinePinning {
			baselineHash, hasBaseline := s.schemaBaselines[pt.name]
			if hasBaseline {
				if baselineHash != pt.hashStr {
					slog.InfoContext(ctx, "Tool schema update/drift detected, updating stored baseline", slog.String("tool", pt.name), slog.String("baseline_hash", baselineHash), slog.String("new_hash", pt.hashStr))
					s.schemaBaselines[pt.name] = pt.hashStr
					writeTasks = append(writeTasks, schemaWriteTask{
						relPath:    pt.name + ".json",
						data:       pt.inputSchema,
						toolRecord: toolRec,
					})
				}
			} else {
				s.schemaBaselines[pt.name] = pt.hashStr
				slog.InfoContext(ctx, "Pinned baseline schema for tool", slog.String("tool", pt.name), slog.String("hash", pt.hashStr))
				writeTasks = append(writeTasks, schemaWriteTask{
					relPath:    pt.name + ".json",
					data:       pt.inputSchema,
					toolRecord: toolRec,
				})
			}
		} else if s.dynamicCapture {
			writeTasks = append(writeTasks, schemaWriteTask{
				relPath:    pt.name + ".json",
				data:       pt.inputSchema,
				toolRecord: toolRec,
			})
		}

		s.schemaCache[pt.name] = pt.inputSchema
		s.schemaCacheLower[strings.ToLower(pt.name)] = pt.inputSchema
	}
	s.mu.Unlock()

	// Marshal aggregate mcp_tools.json OUTSIDE lock
	if s.schemasDir != "" && len(listResp.Tools) > 0 {
		if mcpToolsJSON, err := json.MarshalIndent(listResp.Tools, "", "  "); err == nil {
			writeTasks = append(writeTasks, schemaWriteTask{
				relPath: "mcp_tools.json",
				data:    mcpToolsJSON,
			})
		}
	}

	// Dispatch write-behind tasks to worker channel without blocking critical path
	for _, task := range writeTasks {
		select {
		case s.writeChan <- task:
		case <-s.doneChan:
			return resp, nil
		default:
			slog.WarnContext(ctx, "Write-behind buffer saturated, dropped disk persistence", slog.String("path", task.relPath))
		}
	}

	return resp, nil
}

// ClearBaselines clears all baseline files and in-memory caches.
func (s *SchemaFilter) ClearBaselines() {
	s.mu.Lock()
	s.schemaCache = make(map[string]json.RawMessage)
	s.schemaCacheLower = make(map[string]json.RawMessage)
	s.schemaBaselines = make(map[string]string)
	s.mu.Unlock()

	if s.schemasDir != "" {
		files, err := os.ReadDir(s.schemasDir)
		if err == nil {
			for _, f := range files {
				if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
					_ = os.Remove(filepath.Join(s.schemasDir, f.Name()))
				}
			}
		}
	}
	slog.Info("Pinned baselines and cache cleared on disk and in-memory")
}

// NormalizeJSON produces a deterministic canonical JSON representation for hashing.
func NormalizeJSON(raw json.RawMessage) ([]byte, error) {
	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return json.Marshal(obj)
}

func normalizeJSON(raw json.RawMessage) ([]byte, error) {
	return NormalizeJSON(raw)
}
