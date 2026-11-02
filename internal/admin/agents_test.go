package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestAdminEndpoints_Agents_CRUD_And_Archiving(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. GET /admin/agents returns empty list initially
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var listResp struct {
		Agents []map[string]interface{} `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listResp.Agents) != 0 {
		t.Fatalf("expected 0 agents, got %d", len(listResp.Agents))
	}

	// 2. POST /admin/agents creates a new agent
	createPayload := AgentPayload{
		AgentName:   "agent-alpha",
		Description: "Alpha Test Agent v1",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "test-proto",
				Name:         "test",
				Type:         "stdio",
				Command:      "echo",
				AllowedTools: []string{"ping", "status"},
			},
		},
		EnabledTools: []string{"ping"},
	}
	body, _ := json.Marshal(createPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var createResp struct {
		Status string                 `json:"status"`
		Agent  map[string]interface{} `json:"agent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}
	if createResp.Status != "created" || createResp.Agent["name"] != "agent-alpha" {
		t.Fatalf("unexpected create response: %+v", createResp)
	}

	// Verify disk structure: agents/agent-alpha/current/config.json exists
	currentConfigPath := filepath.Join(agentsDir, "agent-alpha", "current", "config.json")
	if _, err := os.Stat(currentConfigPath); err != nil {
		t.Fatalf("config.json was not created at expected path: %v", err)
	}

	// Duplicate POST should return 409 Conflict
	req = httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on duplicate agent name, got %d", rec.Code)
	}

	// 3. GET /admin/agents/agent-alpha returns agent details
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/agent-alpha", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var getResp struct {
		Name           string               `json:"name"`
		RoutingMode    string               `json:"routing_mode"`
		Config         *agent.RouteConfig   `json:"config"`
		EffectiveTools []agent.ToolMetadata `json:"effective_tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode get response: %v", err)
	}
	if getResp.Name != "agent-alpha" || getResp.Config.Description != "Alpha Test Agent v1" {
		t.Fatalf("unexpected agent details: %+v", getResp)
	}

	// 4. PUT /admin/agents/agent-alpha updates agent and archives prior state
	updatePayload := AgentPayload{
		Description:  "Alpha Test Agent v2",
		RoutingMode:  "direct",
		EnabledTools: []string{"ping", "status"},
	}
	body, _ = json.Marshal(updatePayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/agent-alpha", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on update, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify archive was created
	archiveDir := filepath.Join(agentsDir, "agent-alpha", "archive")
	entries, err := os.ReadDir(archiveDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 archive snapshot after PUT, got %d (err: %v)", len(entries), err)
	}
	snapshotTimestamp := entries[0].Name()

	// 5. Rollback agent to previous snapshot
	rollbackPayload := map[string]string{
		"agent":     "agent-alpha",
		"timestamp": snapshotTimestamp,
	}
	body, _ = json.Marshal(rollbackPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/agents/rollback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on rollback, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify restored config has v1 description
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/agent-alpha", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &getResp)
	if getResp.Config.Description != "Alpha Test Agent v1" {
		t.Errorf("expected rolled back description 'Alpha Test Agent v1', got '%s'", getResp.Config.Description)
	}

	// 6. DELETE /admin/agents/agent-alpha deletes agent
	req = httptest.NewRequest(http.MethodDelete, "/admin/agents/agent-alpha", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify GET now returns 404
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/agent-alpha", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found after deletion, got %d", rec.Code)
	}
}

func TestAdminEndpoints_Agents_ActiveSessionProtection(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// Create agent
	createPayload := AgentPayload{
		AgentName: "active-agent",
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create agent: %d", rec.Code)
	}

	// Set session checker that blocks "active-agent"
	server.SetActiveSessionChecker(func(agentName string) bool {
		return agentName == "active-agent"
	})

	// Attempting DELETE should return 409 Conflict
	req = httptest.NewRequest(http.MethodDelete, "/admin/agents/active-agent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when agent has active sessions, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AGENT_IN_USE") {
		t.Errorf("expected error AGENT_IN_USE, got %s", rec.Body.String())
	}

	// Agent should still exist
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/active-agent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected agent to still exist, got %d", rec.Code)
	}
}

func TestAdminEndpoints_Agents_ManagedModeGuards(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeManaged)
	handler := server.Handler()

	// 1. POST /admin/agents is forbidden
	body := []byte(`{"agent_name": "managed-test"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden in managed mode, got %d", rec.Code)
	}

	// 2. PUT /admin/agents/managed-test is forbidden
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/managed-test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden in managed mode, got %d", rec.Code)
	}

	// 3. DELETE /admin/agents/managed-test is forbidden
	req = httptest.NewRequest(http.MethodDelete, "/admin/agents/managed-test", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden in managed mode, got %d", rec.Code)
	}
}

func TestAdminEndpoints_Agents_ReferentialIntegrityFlow(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. Create protocol "shared-db"
	protoPayload := protocol.Protocol{
		ID:           "shared-db",
		Name:         "shared-db",
		Type:         "stdio",
		Command:      "echo",
		AllowedTools: []string{"query"},
	}
	body, _ := json.Marshal(protoPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create protocol: %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Create agent referencing "shared-db" using ProtocolIDs
	agentPayload := AgentPayload{
		AgentName:   "db-consumer-agent",
		ProtocolIDs: []string{"shared-db"},
	}
	body, _ = json.Marshal(agentPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create agent with protocol reference: %d: %s", rec.Code, rec.Body.String())
	}

	// Verify agent has the protocol attached
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/db-consumer-agent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var agentDetails struct {
		Config *agent.RouteConfig `json:"config"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &agentDetails)
	if len(agentDetails.Config.Protocols) != 1 || agentDetails.Config.Protocols[0].ID != "shared-db" {
		t.Fatalf("expected protocol 'shared-db' attached to agent, got: %+v", agentDetails.Config)
	}

	// 3. Attempt to delete protocol "shared-db" -> must be rejected with 409 Conflict
	req = httptest.NewRequest(http.MethodDelete, "/admin/protocols/shared-db", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when deleting referenced protocol, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROTOCOL_IN_USE") || !strings.Contains(rec.Body.String(), "db-consumer-agent") {
		t.Errorf("expected conflict to mention 'db-consumer-agent', got: %s", rec.Body.String())
	}

	// 4. Delete the referencing agent
	req = httptest.NewRequest(http.MethodDelete, "/admin/agents/db-consumer-agent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to delete agent: %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Now delete protocol "shared-db" -> must succeed with 200 OK!
	req = httptest.NewRequest(http.MethodDelete, "/admin/protocols/shared-db", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after deleting referencing agent, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminEndpoints_Agents_ToolGovernance(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. POST /admin/agents with invalid tool governance mode -> 400 Bad Request
	badPayload := AgentPayload{
		AgentName: "gov-bad-agent",
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"tool1": "not_a_real_mode",
		},
	}
	body, _ := json.Marshal(badPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid governance mode, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_GOVERNANCE_MODE") {
		t.Errorf("expected INVALID_GOVERNANCE_MODE error, got: %s", rec.Body.String())
	}

	// 2. POST /admin/agents with valid 4-mode tool governance -> 201 Created
	validPayload := AgentPayload{
		AgentName: "gov-agent",
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"read_data":    agent.ModeAutonomous,
			"write_data":   agent.ModeGuardedHITL,
			"delete_table": agent.ModeGuardedBlock,
			"deploy_prod":  agent.ModeStrictAlwaysHITL,
		},
	}
	body, _ = json.Marshal(validPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. GET /admin/agents/gov-agent returns configured tool governance
	req = httptest.NewRequest(http.MethodGet, "/admin/agents/gov-agent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var getResp struct {
		Config struct {
			ToolGovernance map[string]agent.ToolGovernanceMode `json:"tool_governance"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode get response: %v", err)
	}
	if len(getResp.Config.ToolGovernance) != 4 {
		t.Fatalf("expected 4 governance entries, got %d", len(getResp.Config.ToolGovernance))
	}
	if getResp.Config.ToolGovernance["deploy_prod"] != agent.ModeStrictAlwaysHITL {
		t.Errorf("expected deploy_prod to be strict_always_hitl, got %s", getResp.Config.ToolGovernance["deploy_prod"])
	}

	// 4. PUT /admin/agents/gov-agent with invalid governance mode -> 400 Bad Request
	putBadPayload := AgentPayload{
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"read_data": "invalid_mode_again",
		},
	}
	body, _ = json.Marshal(putBadPayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/gov-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on PUT invalid governance mode, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. PUT /admin/agents/gov-agent updating governance modes -> 200 OK
	putValidPayload := AgentPayload{
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"read_data":   agent.ModeAutonomous,
			"deploy_prod": agent.ModeGuardedHITL, // changed from strict_always_hitl
		},
	}
	body, _ = json.Marshal(putValidPayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/gov-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PUT update, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify persistence in current/config.json
	currentFile := filepath.Join(agentsDir, "gov-agent", "current", "config.json")
	data, err := os.ReadFile(currentFile)
	if err != nil {
		t.Fatalf("failed to read current config.json: %v", err)
	}
	var savedCfg agent.RouteConfig
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to unmarshal saved config.json: %v", err)
	}
	if savedCfg.ToolGovernance["deploy_prod"] != agent.ModeGuardedHITL {
		t.Errorf("expected deploy_prod to be updated to guarded_hitl on disk, got %s", savedCfg.ToolGovernance["deploy_prod"])
	}
}

func TestAdminEndpoints_Agents_DefensiveProtocolPreservation(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. Create an agent with an attached protocol
	createPayload := AgentPayload{
		AgentName:   "defensive-agent",
		Description: "Agent with active protocols",
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "test-proto",
				Name:    "test",
				Type:    "stdio",
				Command: "echo",
			},
		},
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. PUT with empty / whitespace protocol_ids simulating malformed UI payload
	// The backend MUST NOT wipe existing protocols silently
	putMalformedPayload := AgentPayload{
		Description: "Updated description only",
		ProtocolIDs: []string{"", "   "},
	}
	body, _ = json.Marshal(putMalformedPayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/defensive-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PUT, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify protocols on disk: test-proto must still be preserved!
	currentFile := filepath.Join(agentsDir, "defensive-agent", "current", "config.json")
	data, err := os.ReadFile(currentFile)
	if err != nil {
		t.Fatalf("failed to read current config.json: %v", err)
	}
	var savedCfg agent.RouteConfig
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to unmarshal saved config.json: %v", err)
	}

	if len(savedCfg.Protocols) != 1 || savedCfg.Protocols[0].ID != "test-proto" {
		t.Fatalf("defensive protocol preservation failed: expected 1 protocol ('test-proto'), got %d: %+v",
			len(savedCfg.Protocols), savedCfg.Protocols)
	}

	// 3. PUT with ClearAllProtocols: true should successfully clear protocols
	putClearPayload := AgentPayload{
		ClearAllProtocols: true,
	}
	body, _ = json.Marshal(putClearPayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/defensive-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on clear PUT, got %d: %s", rec.Code, rec.Body.String())
	}

	data, err = os.ReadFile(currentFile)
	if err != nil {
		t.Fatalf("failed to read current config.json: %v", err)
	}
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to unmarshal saved config.json: %v", err)
	}
	if len(savedCfg.Protocols) != 0 {
		t.Fatalf("expected 0 protocols after ClearAllProtocols, got %d", len(savedCfg.Protocols))
	}
}

func TestAdminEndpoints_Agents_GovernanceRetentionAndRestoration(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. Create agent with two protocols (alpha and beta) and tool governance rules
	createPayload := AgentPayload{
		AgentName:   "retention-agent",
		Description: "Retention Test Agent",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "proto-alpha",
				Name:         "alpha",
				Type:         "stdio",
				Command:      "echo",
				AllowedTools: []string{"search", "delete"},
			},
			{
				ID:           "proto-beta",
				Name:         "beta",
				Type:         "stdio",
				Command:      "echo",
				AllowedTools: []string{"read"},
			},
		},
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"proto-alpha__search": agent.ModeGuardedHITL,
			"proto-alpha__delete": agent.ModeStrictAlwaysHITL,
			"proto-beta__read":    agent.ModeAutonomous,
		},
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on agent creation, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Detach proto-alpha by updating protocols with only proto-beta
	putDetachPayload := AgentPayload{
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "proto-beta",
				Name:    "beta",
				Type:    "stdio",
				Command: "echo",
			},
		},
	}
	body, _ = json.Marshal(putDetachPayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/retention-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on detach PUT, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify on disk:
	// - Active ToolGovernance must only contain beta's tool (or nothing from alpha)
	// - RetainedGovernance["proto-alpha"] must contain search and delete!
	currentFile := filepath.Join(agentsDir, "retention-agent", "current", "config.json")
	data, err := os.ReadFile(currentFile)
	if err != nil {
		t.Fatalf("failed to read current config.json: %v", err)
	}
	var savedCfg agent.RouteConfig
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to unmarshal saved config.json: %v", err)
	}

	if _, exists := savedCfg.ToolGovernance["proto-alpha__search"]; exists {
		t.Fatalf("expected proto-alpha__search to be moved out of active ToolGovernance, but it was still present")
	}
	if savedCfg.RetainedGovernance == nil || len(savedCfg.RetainedGovernance["proto-alpha"]) != 2 {
		t.Fatalf("expected proto-alpha to have 2 retained governance rules, got: %+v", savedCfg.RetainedGovernance)
	}
	if savedCfg.RetainedGovernance["proto-alpha"]["proto-alpha__search"] != agent.ModeGuardedHITL {
		t.Fatalf("expected retained search rule to be guarded_hitl, got: %s", savedCfg.RetainedGovernance["proto-alpha"]["proto-alpha__search"])
	}
	if savedCfg.RetainedGovernance["proto-alpha"]["proto-alpha__delete"] != agent.ModeStrictAlwaysHITL {
		t.Fatalf("expected retained delete rule to be strict_always_hitl, got: %s", savedCfg.RetainedGovernance["proto-alpha"]["proto-alpha__delete"])
	}

	// 3. Re-attach proto-alpha with RestoreRetainedProtocols: ["proto-alpha"]
	putRestorePayload := AgentPayload{
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "proto-alpha",
				Name:    "alpha",
				Type:    "stdio",
				Command: "echo",
			},
			{
				ID:      "proto-beta",
				Name:    "beta",
				Type:    "stdio",
				Command: "echo",
			},
		},
		RestoreRetainedProtocols: []string{"proto-alpha"},
	}
	body, _ = json.Marshal(putRestorePayload)
	req = httptest.NewRequest(http.MethodPut, "/admin/agents/retention-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on restore PUT, got %d: %s", rec.Code, rec.Body.String())
	}

	data, err = os.ReadFile(currentFile)
	if err != nil {
		t.Fatalf("failed to read current config.json: %v", err)
	}
	var restoredCfg agent.RouteConfig
	if err := json.Unmarshal(data, &restoredCfg); err != nil {
		t.Fatalf("failed to unmarshal saved config.json: %v", err)
	}

	// Verify active ToolGovernance has restored rules and RetainedGovernance has removed proto-alpha
	if restoredCfg.ToolGovernance["proto-alpha__search"] != agent.ModeGuardedHITL {
		t.Fatalf("restoration failed: expected proto-alpha__search to be guarded_hitl, got %s", restoredCfg.ToolGovernance["proto-alpha__search"])
	}
	if restoredCfg.ToolGovernance["proto-alpha__delete"] != agent.ModeStrictAlwaysHITL {
		t.Fatalf("restoration failed: expected proto-alpha__delete to be strict_always_hitl, got %s", restoredCfg.ToolGovernance["proto-alpha__delete"])
	}
	if len(restoredCfg.RetainedGovernance["proto-alpha"]) != 0 {
		t.Fatalf("expected proto-alpha retained rules to be cleared upon restore, got: %+v", restoredCfg.RetainedGovernance["proto-alpha"])
	}
}

func TestAdminEndpoints_Agents_TrafficPipelineOverrides(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()
	repo := server.agentRepo

	// 1. Create agent with rate_limit and loop_protection
	createPayload := AgentPayload{
		AgentName:   "traffic-agent",
		Description: "Agent with pipeline overrides",
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "proto-1",
				Name:    "proto-1",
				Type:    "stdio",
				Command: "echo",
			},
		},
		RateLimit: &agent.RateLimitOverride{
			MaxBurst:   10,
			RefillRate: 2.5,
		},
		LoopProtection: &agent.LoopProtectionOverride{
			Enabled:       true,
			MaxRepeat:     5,
			WindowSeconds: 20,
			ExcludeTools:  []string{"echo"},
		},
	}

	body, err := json.Marshal(createPayload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify persistence in config.json
	cfg, err := repo.GetAgentConfig("traffic-agent")
	if err != nil {
		t.Fatalf("failed to read agent config: %v", err)
	}
	if cfg.RateLimit == nil || cfg.RateLimit.MaxBurst != 10 || cfg.RateLimit.RefillRate != 2.5 {
		t.Fatalf("rate limit override not saved properly: %+v", cfg.RateLimit)
	}
	if cfg.LoopProtection == nil || !cfg.LoopProtection.Enabled || cfg.LoopProtection.MaxRepeat != 5 || cfg.LoopProtection.WindowSeconds != 20 || len(cfg.LoopProtection.ExcludeTools) != 1 || cfg.LoopProtection.ExcludeTools[0] != "echo" {
		t.Fatalf("loop protection override not saved properly: %+v", cfg.LoopProtection)
	}

	// 2. Update agent: disable loop protection
	putPayload := AgentPayload{
		Protocols: cfg.Protocols,
		RateLimit: &agent.RateLimitOverride{
			MaxBurst:   20,
			RefillRate: 5.0,
		},
		LoopProtection: &agent.LoopProtectionOverride{
			Enabled:       false,
			MaxRepeat:     3,
			WindowSeconds: 10,
		},
	}
	putBody, _ := json.Marshal(putPayload)
	putReq := httptest.NewRequest(http.MethodPut, "/admin/agents/traffic-agent", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	repo.ClearCache()
	updatedCfg, err := repo.GetAgentConfig("traffic-agent")
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}
	if updatedCfg.RateLimit == nil || updatedCfg.RateLimit.MaxBurst != 20 || updatedCfg.RateLimit.RefillRate != 5.0 {
		t.Fatalf("updated rate limit not saved properly: %+v", updatedCfg.RateLimit)
	}
	if updatedCfg.LoopProtection == nil || updatedCfg.LoopProtection.Enabled != false {
		t.Fatalf("updated loop protection should be disabled: %+v", updatedCfg.LoopProtection)
	}

	// 3. Test validation failure on negative values
	invalidPayload := AgentPayload{
		Protocols: cfg.Protocols,
		RateLimit: &agent.RateLimitOverride{
			MaxBurst:   -1,
			RefillRate: 1.0,
		},
	}
	invBody, _ := json.Marshal(invalidPayload)
	invReq := httptest.NewRequest(http.MethodPut, "/admin/agents/traffic-agent", bytes.NewReader(invBody))
	invReq.Header.Set("Content-Type", "application/json")
	invRec := httptest.NewRecorder()
	handler.ServeHTTP(invRec, invReq)

	if invRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for negative rate limit burst, got %d", invRec.Code)
	}
}

func TestAdminEndpoints_Agents_ConcurrentPUT_NoDataRace(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. Create agent initially
	createPayload := AgentPayload{
		AgentName:   "concurrent-agent",
		Description: "Initial Description",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "test-proto",
				Name:         "test",
				Type:         "stdio",
				Command:      "echo",
				AllowedTools: []string{"ping"},
			},
		},
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"test__ping": agent.ModeGuardedHITL,
		},
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create agent: %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Concurrently send PUT requests modifying description and governance
	const workers = 15
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()
			putPayload := AgentPayload{
				Description: fmt.Sprintf("Description updated by worker %d", workerID),
				Protocols: []agent.ProtocolConfig{
					{
						ID:      "test-proto",
						Name:    "test",
						Type:    "stdio",
						Command: "echo",
					},
				},
				ToolGovernance: map[string]agent.ToolGovernanceMode{
					"test__ping": agent.ModeAutonomous,
				},
			}
			pBody, _ := json.Marshal(putPayload)
			pReq := httptest.NewRequest(http.MethodPut, "/admin/agents/concurrent-agent", bytes.NewReader(pBody))
			pReq.Header.Set("Content-Type", "application/json")
			pRec := httptest.NewRecorder()
			handler.ServeHTTP(pRec, pReq)
			if pRec.Code != http.StatusOK {
				t.Errorf("worker %d: expected 200 OK, got %d: %s", workerID, pRec.Code, pRec.Body.String())
			}
		}(i)
	}

	wg.Wait()

	// Verify agent file remains valid JSON and can be loaded
	repo := agent.NewFSRepository(agentsDir, "")
	cfg, err := repo.GetAgentConfig("concurrent-agent")
	if err != nil {
		t.Fatalf("failed to read agent config after concurrent PUTs: %v", err)
	}
	if cfg.ToolGovernance == nil || cfg.ToolGovernance["test__ping"] != agent.ModeAutonomous {
		t.Errorf("expected tool governance to be ModeAutonomous, got %+v", cfg.ToolGovernance)
	}
}

func TestAdminEndpoints_Agents_DetachedProtocol_RetainsGovernance(t *testing.T) {
	server, _, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()
	repo := agent.NewFSRepository(agentsDir, "")

	// 1. Create agent with two protocols
	createPayload := AgentPayload{
		AgentName:   "retention-agent",
		Description: "Multi-Protocol Retention Agent",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "proto-a",
				Name:    "proto-a",
				Type:    "stdio",
				Command: "echo",
			},
			{
				ID:      "proto-b",
				Name:    "proto-b",
				Type:    "stdio",
				Command: "echo",
			},
		},
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			"proto-a__tool1": agent.ModeGuardedHITL,
			"proto-b__tool2": agent.ModeStrictAlwaysHITL,
		},
	}
	body, _ := json.Marshal(createPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create agent: %d: %s", rec.Code, rec.Body.String())
	}

	// Seed manifest so toolBelongsToProtocol can resolve tool names
	_ = repo.SaveAgentManifest("retention-agent", []map[string]interface{}{
		{"name": "proto-a__tool1", "protocol_name": "proto-a", "protocol_id": "proto-a"},
		{"name": "proto-b__tool2", "protocol_name": "proto-b", "protocol_id": "proto-b"},
	})

	// 2. Detach proto-b by only including proto-a in PUT payload
	putPayload := AgentPayload{
		Protocols: []agent.ProtocolConfig{
			{
				ID:      "proto-a",
				Name:    "proto-a",
				Type:    "stdio",
				Command: "echo",
			},
		},
	}
	putBody, _ := json.Marshal(putPayload)
	putReq := httptest.NewRequest(http.MethodPut, "/admin/agents/retention-agent", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on detach PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	repo.ClearCache()
	cfg, err := repo.GetAgentConfig("retention-agent")
	if err != nil {
		t.Fatalf("failed to load agent config: %v", err)
	}

	// Verify retained governance holds proto-b's rule
	if cfg.RetainedGovernance == nil || cfg.RetainedGovernance["proto-b"] == nil {
		t.Fatalf("expected retained_governance for proto-b, got: %+v", cfg.RetainedGovernance)
	}
	if cfg.RetainedGovernance["proto-b"]["proto-b__tool2"] != agent.ModeStrictAlwaysHITL {
		t.Errorf("expected retained rule for proto-b__tool2 to be strict_always_hitl, got: %s", cfg.RetainedGovernance["proto-b"]["proto-b__tool2"])
	}

	// Active tool governance should no longer contain proto-b__tool2
	if _, exists := cfg.ToolGovernance["proto-b__tool2"]; exists {
		t.Errorf("detached tool proto-b__tool2 should have been purged from active ToolGovernance")
	}
	// Active tool governance should still contain proto-a__tool1
	if cfg.ToolGovernance["proto-a__tool1"] != agent.ModeGuardedHITL {
		t.Errorf("active tool proto-a__tool1 should still be guarded_hitl, got: %s", cfg.ToolGovernance["proto-a__tool1"])
	}
}



