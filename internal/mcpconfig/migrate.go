package mcpconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

// MigrateOptions configures the multi-store legacy protocol ID migration engine.
type MigrateOptions struct {
	ProtocolsDir  string
	AgentsDir     string
	SchemasDir    string
	ProtocolStore protocol.Store
	SchemaStore   schema.Store
	PolicyStore   policy.Store
}

// protocolSchemaMigrator is implemented by schema stores (such as DuckDBSchemaStore)
// capable of renaming tool schema records in place while preserving `is_pinned`.
type protocolSchemaMigrator interface {
	MigrateProtocolSchemas(ctx context.Context, oldProtoID, newProtoID string, formatToolName func(protoID, rawTool string) string) error
}

// resolveCompactProtocolID checks whether protoID is a legacy bloated identifier
// (`<profile>_<full_path>_<6hex>`) and returns `(newID, true)` when it should be migrated.
func resolveCompactProtocolID(defaultProfile, protoID, protoName string) (string, bool) {
	id := strings.TrimSpace(protoID)
	if id == "" {
		return "", false
	}

	// 1. Check if protoName carries the canonical "<rawServerName> (<profile>)" suffix from adopt.
	name := strings.TrimSpace(protoName)
	if openIdx := strings.LastIndex(name, " ("); openIdx > 0 && strings.HasSuffix(name, ")") {
		rawServer := name[:openIdx]
		prof := strings.TrimSpace(name[openIdx+2 : len(name)-1])
		if prof != "" && rawServer != "" {
			legacyID := legacySanitizeIdentifier(prof, rawServer)
			newID := sanitizeIdentifier(prof, rawServer)
			if strings.EqualFold(id, legacyID) && !strings.EqualFold(id, newID) {
				return newID, true
			}
		}
	}

	// 2. Also check against defaultProfile if protoName was customized.
	if defaultProfile != "" && name != "" {
		legacyID := legacySanitizeIdentifier(defaultProfile, name)
		newID := sanitizeIdentifier(defaultProfile, name)
		if strings.EqualFold(id, legacyID) && !strings.EqualFold(id, newID) {
			return newID, true
		}
	}

	// 3. Heuristic match for any >15-char identifier ending in `_[0-9a-f]{6}` (legacy 6-hex hash).
	lowerID := strings.ToLower(id)
	if len(lowerID) > 15 {
		if uIdx := strings.LastIndexByte(lowerID, '_'); uIdx > 0 {
			suffix := lowerID[uIdx+1:]
			if len(suffix) == 6 && agent.IsHexString(suffix) {
				compacted := agent.CompactLegacyProtocolSlug(lowerID)
				if compacted != "" && compacted != lowerID {
					return compacted, true
				}
			}
		}
	}

	return "", false
}

// CountPendingLegacyProtocolIDs inspects protocols/ and agents/*/current/ in read-only mode
// and returns the count of legacy bloated protocol IDs eligible for migration.
func CountPendingLegacyProtocolIDs(opts MigrateOptions) int {
	protocolsDir, agentsDir := resolveMigrateDirs(opts)
	_, lowerIDMap, _ := discoverLegacyProtocolIDMappings(protocolsDir, agentsDir)
	return len(lowerIDMap)
}

func resolveMigrateDirs(opts MigrateOptions) (string, string) {
	protocolsDir := opts.ProtocolsDir
	if protocolsDir == "" {
		protocolsDir = filepath.Join(config.DefaultFaradAiWireDir(), "protocols")
	}
	agentsDir := opts.AgentsDir
	if agentsDir == "" {
		agentsDir = filepath.Join(config.DefaultFaradAiWireDir(), "agents")
	}
	return protocolsDir, agentsDir
}

func discoverLegacyProtocolIDMappings(protocolsDir, agentsDir string) (map[string]string, map[string]string, []os.DirEntry) {
	idMap := make(map[string]string)
	lowerIDMap := make(map[string]string)

	recordMapping := func(oldID, newID string) {
		if oldID == "" || newID == "" || strings.EqualFold(oldID, newID) {
			return
		}
		idMap[oldID] = newID
		lowerIDMap[strings.ToLower(oldID)] = newID
	}

	// 1. Discover legacy protocol files in protocolsDir
	if entries, err := os.ReadDir(protocolsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			fileID := strings.TrimSuffix(entry.Name(), ".json")
			pPath, pErr := pathguard.ResolveSandboxedPath(protocolsDir, entry.Name())
			if pErr != nil {
				continue
			}
			data, rErr := os.ReadFile(pPath)
			if rErr != nil {
				continue
			}
			var p protocol.Protocol
			if json.Unmarshal(data, &p) != nil {
				continue
			}
			effectiveOldID := p.ID
			if effectiveOldID == "" {
				effectiveOldID = fileID
			}
			if newID, ok := resolveCompactProtocolID("", effectiveOldID, p.Name); ok {
				recordMapping(effectiveOldID, newID)
				if fileID != effectiveOldID {
					recordMapping(fileID, newID)
				}
			}
		}
	}

	// 2. Discover legacy protocol references inside agents/*/current/config.json
	agentEntries, _ := os.ReadDir(agentsDir)
	for _, ae := range agentEntries {
		if !ae.IsDir() {
			continue
		}
		profileName := ae.Name()
		agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, profileName)
		if err != nil {
			continue
		}
		currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
		if err != nil {
			continue
		}
		cfgPath, err := pathguard.ResolveSandboxedPath(currentDir, "config.json")
		if err != nil {
			continue
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil || len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		var routeCfg agent.RouteConfig
		if json.Unmarshal(data, &routeCfg) != nil {
			continue
		}
		for _, ep := range routeCfg.Protocols {
			if newID, ok := resolveCompactProtocolID(profileName, ep.ID, ep.Name); ok {
				recordMapping(ep.ID, newID)
			}
		}
		for retainedProtoID := range routeCfg.RetainedGovernance {
			if newID, ok := resolveCompactProtocolID(profileName, retainedProtoID, ""); ok {
				recordMapping(retainedProtoID, newID)
			}
		}
	}

	return idMap, lowerIDMap, agentEntries
}

// MigrateLegacyProtocolIDs scans protocols/ and agents/*/current/ for legacy bloated protocol IDs
// (`antigravity_codegraph_696cf8`, `cline_github_com_..._516fbc`) and atomically upgrades them to
// compact `<stem_max10>_<4hex>` identifiers across disk files and DuckDB stores.
// It is 100% idempotent and returns the number of migrated protocol mappings.
func MigrateLegacyProtocolIDs(ctx context.Context, opts MigrateOptions) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	protocolsDir, agentsDir := resolveMigrateDirs(opts)
	idMap, lowerIDMap, agentEntries := discoverLegacyProtocolIDMappings(protocolsDir, agentsDir)
	if len(lowerIDMap) == 0 {
		return 0, nil
	}

	// 3. Migrate protocol definition files in protocolsDir (write newID before updating agents or removing oldID)
	for oldID, newID := range idMap {
		if err := migrateProtocolFile(protocolsDir, opts.ProtocolStore, oldID, newID); err != nil {
			return 0, err
		}
	}

	var errs []error

	// 4. Migrate each agent profile (config.json, tools_manifest.json, dlp.json, and PolicyStore)
	for _, ae := range agentEntries {
		if !ae.IsDir() {
			continue
		}
		profileName := ae.Name()
		agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, profileName)
		if err != nil {
			continue
		}
		currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
		if err != nil {
			continue
		}
		if fi, err := os.Stat(currentDir); err != nil || !fi.IsDir() {
			continue
		}

		cfgPath, err := pathguard.ResolveSandboxedPath(currentDir, "config.json")
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve config path for '%s': %w", profileName, err))
			continue
		}
		if err := migrateAgentConfigFile(cfgPath, lowerIDMap); err != nil {
			return 0, err
		}

		manifestPath, err := pathguard.ResolveSandboxedPath(currentDir, "tools_manifest.json")
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve manifest path for '%s': %w", profileName, err))
			continue
		}
		if err := migrateAgentManifestFile(manifestPath, lowerIDMap); err != nil {
			return 0, err
		}

		dlpPath, err := pathguard.ResolveSandboxedPath(currentDir, "dlp.json")
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve dlp path for '%s': %w", profileName, err))
			continue
		}
		if err := migrateAgentDLPFile(dlpPath, lowerIDMap); err != nil {
			return 0, err
		}

		if opts.PolicyStore != nil {
			if pErr := migrateAgentPolicyStore(ctx, opts.PolicyStore, profileName, lowerIDMap); pErr != nil {
				errs = append(errs, fmt.Errorf("migrate policy store for '%s': %w", profileName, pErr))
			}
		}
	}

	// 5. Migrate DuckDB mcp_tool_schemas and disk schemasDir baselines
	if sm, ok := opts.SchemaStore.(protocolSchemaMigrator); ok && sm != nil {
		for oldID, newID := range idMap {
			if err := sm.MigrateProtocolSchemas(ctx, oldID, newID, agent.FormatAggregatedToolName); err != nil {
				return 0, err
			}
			if lowerOld := strings.ToLower(oldID); lowerOld != oldID {
				if err := sm.MigrateProtocolSchemas(ctx, lowerOld, newID, agent.FormatAggregatedToolName); err != nil {
					errs = append(errs, fmt.Errorf("migrate lowercase schema rows for '%s': %w", lowerOld, err))
				}
			}
		}
	}
	if opts.SchemasDir != "" {
		if sErr := migrateSchemasDir(opts.SchemasDir, lowerIDMap); sErr != nil {
			errs = append(errs, fmt.Errorf("migrate schemas directory '%s': %w", opts.SchemasDir, sErr))
		}
	}

	// 6. Clean up legacy protocol files in protocolsDir ONLY if no current config or archive snapshot references oldID
	stillReferenced := collectReferencedProtocolIDs(agentsDir)
	for oldID := range idMap {
		if stillReferenced[strings.ToLower(oldID)] {
			continue
		}
		if opts.ProtocolStore != nil {
			if dErr := opts.ProtocolStore.Delete(oldID); dErr != nil && !errors.Is(dErr, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("delete legacy protocol '%s' from store: %w", oldID, dErr))
			}
		}
		if oldPath, err := pathguard.ResolveSandboxedPath(protocolsDir, oldID+".json"); err == nil {
			if rErr := os.Remove(oldPath); rErr != nil && !os.IsNotExist(rErr) {
				errs = append(errs, fmt.Errorf("remove legacy protocol file '%s': %w", oldPath, rErr))
			}
		}
	}

	if err := errors.Join(errs...); err != nil {
		return len(lowerIDMap), err
	}
	return len(lowerIDMap), nil
}

func migrateProtocolFile(protocolsDir string, store protocol.Store, oldID, newID string) error {
	oldPath, err := pathguard.ResolveSandboxedPath(protocolsDir, oldID+".json")
	if err != nil {
		return nil
	}
	oldBytes, rErr := os.ReadFile(oldPath)
	if rErr != nil {
		if os.IsNotExist(rErr) {
			return nil
		}
		return rErr
	}
	var oldProto protocol.Protocol
	if err := json.Unmarshal(oldBytes, &oldProto); err != nil {
		return nil
	}

	newPath, err := pathguard.ResolveSandboxedPath(protocolsDir, newID+".json")
	if err != nil {
		return err
	}

	targetProto := oldProto
	targetProto.ID = newID

	// If newPath already exists, preserve any user edits on existingNew over legacy targetProto
	if newBytes, nErr := os.ReadFile(newPath); nErr == nil {
		var existingNew protocol.Protocol
		if json.Unmarshal(newBytes, &existingNew) == nil {
			mergePreservedProtocol(&existingNew, &targetProto)
			existingNew.ID = newID
			targetProto = existingNew
		}
	}

	if store != nil {
		if err := store.Save(&targetProto); err == nil {
			return nil
		}
	}

	outBytes, err := json.MarshalIndent(&targetProto, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(newPath, outBytes, 0600)
}

func rewriteToolNameWithMap(toolName string, lowerIDMap map[string]string) (string, bool) {
	if !strings.Contains(toolName, "__") {
		return toolName, false
	}
	parts := strings.SplitN(toolName, "__", 2)
	newID, ok := lowerIDMap[strings.ToLower(strings.TrimSpace(parts[0]))]
	if !ok {
		return toolName, false
	}
	return agent.FormatAggregatedToolName(newID, parts[1]), true
}

func rewriteToolSlice(list []string, lowerIDMap map[string]string) ([]string, bool) {
	if len(list) == 0 {
		return list, false
	}
	changed := false
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, item := range list {
		rewritten, ok := rewriteToolNameWithMap(item, lowerIDMap)
		if ok && rewritten != item {
			changed = true
		}
		key := strings.ToLower(rewritten)
		if !seen[key] {
			seen[key] = true
			out = append(out, rewritten)
		} else {
			changed = true
		}
	}
	return out, changed
}

func migrateAgentConfigFile(cfgPath string, lowerIDMap map[string]string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var routeCfg agent.RouteConfig
	if err := json.Unmarshal(data, &routeCfg); err != nil {
		return nil
	}

	changed := false

	// 1. Migrate attached Protocols (deduplicating if both oldID and newID exist)
	if len(routeCfg.Protocols) > 0 {
		byID := make(map[string]agent.ProtocolConfig, len(routeCfg.Protocols))
		order := make([]string, 0, len(routeCfg.Protocols))
		for _, p := range routeCfg.Protocols {
			targetID := p.ID
			if mapped, ok := lowerIDMap[strings.ToLower(strings.TrimSpace(p.ID))]; ok {
				targetID = mapped
				changed = true
			}
			p.ID = targetID
			if newAllowed, aChanged := rewriteToolSlice(p.AllowedTools, lowerIDMap); aChanged {
				p.AllowedTools = newAllowed
				changed = true
			}
			if prev, exists := byID[targetID]; exists {
				mergePreservedProtocolConfig(&p, &prev)
				changed = true
			} else {
				order = append(order, targetID)
			}
			byID[targetID] = p
		}
		merged := make([]agent.ProtocolConfig, 0, len(order))
		for _, id := range order {
			merged = append(merged, byID[id])
		}
		sort.Slice(merged, func(i, j int) bool {
			return merged[i].ID < merged[j].ID
		})
		routeCfg.Protocols = merged
	}

	// 2. EnabledTools & ToolOverrides.EnabledTools
	if list, c := rewriteToolSlice(routeCfg.EnabledTools, lowerIDMap); c {
		routeCfg.EnabledTools = list
		changed = true
	}
	if routeCfg.ToolOverrides != nil {
		if list, c := rewriteToolSlice(routeCfg.ToolOverrides.EnabledTools, lowerIDMap); c {
			routeCfg.ToolOverrides.EnabledTools = list
			changed = true
		}
	}

	// 3. LoopProtection.ExcludeTools
	if routeCfg.LoopProtection != nil {
		if list, c := rewriteToolSlice(routeCfg.LoopProtection.ExcludeTools, lowerIDMap); c {
			routeCfg.LoopProtection.ExcludeTools = list
			changed = true
		}
	}

	// 4. ToolGovernance
	if len(routeCfg.ToolGovernance) > 0 {
		newGov := make(map[string]agent.ToolGovernanceMode, len(routeCfg.ToolGovernance))
		for k, mode := range routeCfg.ToolGovernance {
			rk, c := rewriteToolNameWithMap(k, lowerIDMap)
			if c && rk != k {
				changed = true
			}
			newGov[rk] = mode
		}
		routeCfg.ToolGovernance = newGov
	}

	// 5. RetainedGovernance
	if len(routeCfg.RetainedGovernance) > 0 {
		newRetained := make(map[string]map[string]agent.ToolGovernanceMode, len(routeCfg.RetainedGovernance))
		for protoKey, govMap := range routeCfg.RetainedGovernance {
			targetProtoKey := protoKey
			if mapped, ok := lowerIDMap[strings.ToLower(strings.TrimSpace(protoKey))]; ok {
				targetProtoKey = mapped
				changed = true
			}
			inner := newRetained[targetProtoKey]
			if inner == nil {
				inner = make(map[string]agent.ToolGovernanceMode, len(govMap))
			}
			for tk, mode := range govMap {
				rtk, c := rewriteToolNameWithMap(tk, lowerIDMap)
				if c && rtk != tk {
					changed = true
				}
				inner[rtk] = mode
			}
			newRetained[targetProtoKey] = inner
		}
		routeCfg.RetainedGovernance = newRetained
	}

	if !changed {
		return nil
	}

	outBytes, err := json.MarshalIndent(routeCfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(cfgPath, outBytes, 0600)
}

func migrateAgentManifestFile(manifestPath string, lowerIDMap map[string]string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var tools []agent.ToolMetadata
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil
	}

	changed := false
	dedup := make(map[string]agent.ToolMetadata, len(tools))
	order := make([]string, 0, len(tools))

	for _, t := range tools {
		newID, ok := lowerIDMap[strings.ToLower(strings.TrimSpace(t.ProtocolID))]
		if !ok && strings.Contains(t.Name, "__") {
			parts := strings.SplitN(t.Name, "__", 2)
			newID, ok = lowerIDMap[strings.ToLower(strings.TrimSpace(parts[0]))]
		}
		if ok {
			raw := t.RawName
			if raw == "" {
				if strings.Contains(t.Name, "__") {
					raw = strings.SplitN(t.Name, "__", 2)[1]
				} else {
					raw = t.Name
				}
			}
			formatted := agent.FormatAggregatedToolName(newID, raw)
			if t.ProtocolID != newID || t.Name != formatted || t.CanonicalName != formatted {
				t.ProtocolID = newID
				t.Name = formatted
				t.CanonicalName = formatted
				t.RawName = raw
				changed = true
			}
		}
		key := strings.ToLower(t.Name)
		if _, exists := dedup[key]; !exists {
			order = append(order, key)
		} else {
			changed = true
		}
		dedup[key] = t
	}

	if !changed {
		return nil
	}

	outTools := make([]agent.ToolMetadata, 0, len(order))
	for _, k := range order {
		outTools = append(outTools, dedup[k])
	}
	sort.Slice(outTools, func(i, j int) bool {
		return outTools[i].Name < outTools[j].Name
	})

	outBytes, err := json.MarshalIndent(outTools, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(manifestPath, outBytes, 0600)
}

func migrateAgentDLPFile(dlpPath string, lowerIDMap map[string]string) error {
	data, err := os.ReadFile(dlpPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}

	exemptRaw, ok := doc["tool_exemptions"].(map[string]interface{})
	if !ok || len(exemptRaw) == 0 {
		return nil
	}

	changed := false
	newExempt := make(map[string]interface{}, len(exemptRaw))
	for k, v := range exemptRaw {
		rk, c := rewriteToolNameWithMap(k, lowerIDMap)
		if c && rk != k {
			changed = true
		}
		newExempt[rk] = v
	}
	if !changed {
		return nil
	}

	doc["tool_exemptions"] = newExempt
	outBytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(dlpPath, outBytes, 0600)
}

func migrateAgentPolicyStore(ctx context.Context, store policy.Store, agentName string, lowerIDMap map[string]string) error {
	cfg, err := store.GetAgentConfig(ctx, agentName)
	if err != nil {
		if errors.Is(err, policy.ErrConfigNotFound) {
			return nil
		}
		return err
	}
	if cfg == nil || len(cfg.ToolExemptions) == 0 {
		return nil
	}

	changed := false
	newExempt := make(map[string]policy.ToolExemption, len(cfg.ToolExemptions))
	for k, v := range cfg.ToolExemptions {
		rk, c := rewriteToolNameWithMap(k, lowerIDMap)
		if c && rk != k {
			changed = true
		}
		newExempt[rk] = v
	}
	if !changed {
		return nil
	}
	cfg.ToolExemptions = newExempt
	return store.SaveAgentConfig(ctx, cfg)
}

func migrateSchemasDir(schemasDir string, lowerIDMap map[string]string) error {
	entries, err := os.ReadDir(schemasDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Name() == "mcp_tools.json" {
			// Rewrite top-level tool keys inside mcp_tools.json if present
			p, pErr := pathguard.ResolveSandboxedPath(schemasDir, "mcp_tools.json")
			if pErr != nil {
				errs = append(errs, pErr)
				continue
			}
			raw, rErr := os.ReadFile(p)
			if rErr != nil {
				if !os.IsNotExist(rErr) {
					errs = append(errs, rErr)
				}
				continue
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
				continue
			}
			changed := false
			nm := make(map[string]json.RawMessage, len(m))
			for k, v := range m {
				rk, c := rewriteToolNameWithMap(k, lowerIDMap)
				if c && rk != k {
					changed = true
				}
				nm[rk] = v
			}
			if changed {
				out, mErr := json.MarshalIndent(nm, "", "  ")
				if mErr != nil {
					errs = append(errs, mErr)
				} else if wErr := atomicWriteFile(p, out, 0600); wErr != nil {
					errs = append(errs, wErr)
				}
			}
			continue
		}

		toolName := strings.TrimSuffix(entry.Name(), ".json")
		newToolName, changed := rewriteToolNameWithMap(toolName, lowerIDMap)
		if !changed || newToolName == toolName {
			continue
		}
		oldPath, err1 := pathguard.ResolveSandboxedPath(schemasDir, entry.Name())
		newPath, err2 := pathguard.ResolveSandboxedPath(schemasDir, newToolName+".json")
		if err1 != nil || err2 != nil {
			errs = append(errs, errors.Join(err1, err2))
			continue
		}
		if _, statErr := os.Stat(newPath); os.IsNotExist(statErr) {
			if rErr := os.Rename(oldPath, newPath); rErr != nil {
				errs = append(errs, rErr)
			}
		} else if rErr := os.Remove(oldPath); rErr != nil && !os.IsNotExist(rErr) {
			errs = append(errs, rErr)
		}
	}
	return errors.Join(errs...)
}

func collectProtocolRefsFromConfig(cfgPath string, refs map[string]bool) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	var rc agent.RouteConfig
	if json.Unmarshal(data, &rc) != nil {
		return
	}
	for _, p := range rc.Protocols {
		if id := strings.ToLower(strings.TrimSpace(p.ID)); id != "" {
			refs[id] = true
		}
	}
	for k := range rc.RetainedGovernance {
		if id := strings.ToLower(strings.TrimSpace(k)); id != "" {
			refs[id] = true
		}
	}
}

func collectReferencedProtocolIDs(agentsDir string) map[string]bool {
	refs := make(map[string]bool)
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		return refs
	}
	for _, ae := range entries {
		if !ae.IsDir() {
			continue
		}
		agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, ae.Name())
		if err != nil {
			continue
		}
		if currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current"); err == nil {
			if cfgPath, err := pathguard.ResolveSandboxedPath(currentDir, "config.json"); err == nil {
				collectProtocolRefsFromConfig(cfgPath, refs)
			}
		}
		// Never delete legacy protocol files if any archived snapshot still references them.
		if archiveDir, err := pathguard.ResolveSandboxedPath(agentDir, "archive"); err == nil {
			if snaps, sErr := os.ReadDir(archiveDir); sErr == nil {
				for _, snap := range snaps {
					if !snap.IsDir() {
						continue
					}
					if snapDir, err := pathguard.ResolveSandboxedPath(archiveDir, snap.Name()); err == nil {
						if snapCfg, err := pathguard.ResolveSandboxedPath(snapDir, "config.json"); err == nil {
							collectProtocolRefsFromConfig(snapCfg, refs)
						}
					}
				}
			}
		}
	}
	return refs
}
