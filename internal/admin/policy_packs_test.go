package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

func setupTestAdminServerWithPolicy(t *testing.T) (*AdminServer, *policy.DuckDBStore, *policy.Compiler, string) {
	t.Helper()

	store, err := policy.OpenDuckDBStore(":memory:")
	if err != nil {
		t.Fatalf("failed to open duckdb store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}
	if err := policy.Seed(ctx, store); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	tempAgentsDir := t.TempDir()
	compiler := policy.NewCompiler(store, policy.WithAgentsDir(tempAgentsDir))
	agentRepo := agent.NewFSRepository(tempAgentsDir)

	server := NewAdminServer(nil, nil, nil)
	server.SetAgentRepository(agentRepo)
	server.SetPolicyStore(store)
	server.SetPolicyCompiler(compiler)

	return server, store, compiler, tempAgentsDir
}

func TestPolicyPackHandlers_DlpRules(t *testing.T) {
	server, _, _, _ := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	// 1. GET /admin/dlp/rules (must list seeded rules)
	req := httptest.NewRequest(http.MethodGet, "/admin/dlp/rules", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/dlp/rules failed with status %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Rules []policy.DlpPatternRule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode rules response failed: %v", err)
	}
	if len(listResp.Rules) == 0 {
		t.Fatalf("expected seeded rules in response, got 0")
	}

	// Filter by category: ?category=kvkk
	reqCat := httptest.NewRequest(http.MethodGet, "/admin/dlp/rules?category=kvkk", nil)
	recCat := httptest.NewRecorder()
	handler.ServeHTTP(recCat, reqCat)

	if recCat.Code != http.StatusOK {
		t.Fatalf("GET /admin/dlp/rules?category=kvkk failed with status %d", recCat.Code)
	}
	var catResp struct {
		Rules []policy.DlpPatternRule `json:"rules"`
	}
	_ = json.Unmarshal(recCat.Body.Bytes(), &catResp)
	for _, r := range catResp.Rules {
		if r.Category != "kvkk" {
			t.Errorf("expected category kvkk, got %s", r.Category)
		}
	}

	// 2. POST /admin/dlp/rules (create custom rule)
	customRule := policy.DlpPatternRule{
		ID:            "rule:custom-tax",
		Name:          "Custom Tax Number",
		Description:   "Matches local tax pattern",
		Category:      "custom",
		Regex:         `\bTAX-[0-9]{8}\b`,
		DefaultAction: policy.ActionMask,
	}
	body, _ := json.Marshal(customRule)
	reqCreate := httptest.NewRequest(http.MethodPost, "/admin/dlp/rules", bytes.NewReader(body))
	recCreate := httptest.NewRecorder()
	handler.ServeHTTP(recCreate, reqCreate)

	if recCreate.Code != http.StatusCreated {
		t.Fatalf("POST /admin/dlp/rules failed with %d: %s", recCreate.Code, recCreate.Body.String())
	}

	// 3. GET /admin/dlp/rules/{id}
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/dlp/rules/rule:custom-tax", nil)
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /admin/dlp/rules/rule:custom-tax failed with %d: %s", recGet.Code, recGet.Body.String())
	}

	// 4. PUT /admin/dlp/rules/{id} (update custom rule)
	customRule.Description = "Updated tax description"
	customRule.DefaultAction = policy.ActionBlock
	bodyUpdate, _ := json.Marshal(customRule)
	reqUpdate := httptest.NewRequest(http.MethodPut, "/admin/dlp/rules/rule:custom-tax", bytes.NewReader(bodyUpdate))
	recUpdate := httptest.NewRecorder()
	handler.ServeHTTP(recUpdate, reqUpdate)

	if recUpdate.Code != http.StatusOK {
		t.Fatalf("PUT /admin/dlp/rules/rule:custom-tax failed with %d: %s", recUpdate.Code, recUpdate.Body.String())
	}

	// Attempt to update builtin rule must return 403 Forbidden
	builtinUpdate := policy.DlpPatternRule{
		ID:            "rule:tr-tckn",
		Name:          "Hacked TCKN",
		Category:      "kvkk",
		Regex:         `\b[0-9]{11}\b`,
		DefaultAction: policy.ActionBlock,
	}
	bodyBuiltin, _ := json.Marshal(builtinUpdate)
	reqBuiltin := httptest.NewRequest(http.MethodPut, "/admin/dlp/rules/rule:tr-tckn", bytes.NewReader(bodyBuiltin))
	recBuiltin := httptest.NewRecorder()
	handler.ServeHTTP(recBuiltin, reqBuiltin)

	if recBuiltin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on updating builtin rule, got %d", recBuiltin.Code)
	}

	// 5. DELETE /admin/dlp/rules/{id}
	reqDelete := httptest.NewRequest(http.MethodDelete, "/admin/dlp/rules/rule:custom-tax", nil)
	recDelete := httptest.NewRecorder()
	handler.ServeHTTP(recDelete, reqDelete)

	if recDelete.Code != http.StatusOK {
		t.Fatalf("DELETE /admin/dlp/rules/rule:custom-tax failed with %d", recDelete.Code)
	}
}

func TestPolicyPackHandlers_PolicyPacks(t *testing.T) {
	server, _, _, _ := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	// 1. GET /admin/policy-packs (must return seeded packs)
	req := httptest.NewRequest(http.MethodGet, "/admin/policy-packs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/policy-packs failed with %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Packs []policy.PolicyPack `json:"packs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal packs failed: %v", err)
	}
	if len(listResp.Packs) != len(policy.BuiltinPacks()) {
		t.Fatalf("expected %d seeded packs, got %d", len(policy.BuiltinPacks()), len(listResp.Packs))
	}

	// 2. GET /admin/policy-packs/{id} (must return pack with populated rules)
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/policy-packs/pack:tr-kvkk", nil)
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /admin/policy-packs/pack:tr-kvkk failed with %d: %s", recGet.Code, recGet.Body.String())
	}
	var getResp struct {
		Pack policy.PolicyPack `json:"pack"`
	}
	_ = json.Unmarshal(recGet.Body.Bytes(), &getResp)
	if len(getResp.Pack.Rules) == 0 {
		t.Fatalf("expected populated rules in pack, got 0")
	}

	// 3. POST /admin/policy-packs (create custom pack)
	customPack := policy.PolicyPack{
		ID:          "pack:internal-compliance",
		Name:        "Internal Compliance",
		Description: "Internal rules",
		Category:    "custom",
		RuleIDs:     []string{"rule:tr-tckn", "rule:cloud-jwt"},
	}
	body, _ := json.Marshal(customPack)
	reqCreate := httptest.NewRequest(http.MethodPost, "/admin/policy-packs", bytes.NewReader(body))
	recCreate := httptest.NewRecorder()
	handler.ServeHTTP(recCreate, reqCreate)

	if recCreate.Code != http.StatusCreated {
		t.Fatalf("POST /admin/policy-packs failed with %d: %s", recCreate.Code, recCreate.Body.String())
	}

	// 4. PUT /admin/policy-packs/{id} (update custom pack)
	customPack.Description = "Updated internal rules"
	bodyUpdate, _ := json.Marshal(customPack)
	reqUpdate := httptest.NewRequest(http.MethodPut, "/admin/policy-packs/pack:internal-compliance", bytes.NewReader(bodyUpdate))
	recUpdate := httptest.NewRecorder()
	handler.ServeHTTP(recUpdate, reqUpdate)

	if recUpdate.Code != http.StatusOK {
		t.Fatalf("PUT /admin/policy-packs failed with %d", recUpdate.Code)
	}

	// 5. DELETE /admin/policy-packs/{id}
	reqDelete := httptest.NewRequest(http.MethodDelete, "/admin/policy-packs/pack:internal-compliance", nil)
	recDelete := httptest.NewRecorder()
	handler.ServeHTTP(recDelete, reqDelete)

	if recDelete.Code != http.StatusOK {
		t.Fatalf("DELETE /admin/policy-packs failed with %d", recDelete.Code)
	}
}

func TestPolicyPackHandlers_AgentDLP(t *testing.T) {
	server, _, _, tempAgentsDir := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	agentName := "customer-support"

	// 1. GET /admin/agents/{name}/dlp (initial unconfigured state returns empty defaults)
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/agents/"+agentName+"/dlp", nil)
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET agent dlp failed with %d: %s", recGet.Code, recGet.Body.String())
	}

	var getResp struct {
		AgentName string                   `json:"agent_name"`
		Config    policy.AgentPolicyConfig `json:"config"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode agent dlp response failed: %v", err)
	}
	if getResp.AgentName != agentName {
		t.Errorf("expected agent_name %s, got %s", agentName, getResp.AgentName)
	}

	// Seed agent directory with config.json
	currentDir := filepath.Join(tempAgentsDir, agentName, "current")
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		t.Fatalf("failed to create agent current dir: %v", err)
	}
	seedConfig := `{"agent_id":"customer-support","agent_name":"customer-support","routing_mode":"aggregated"}`
	if err := os.WriteFile(filepath.Join(currentDir, "config.json"), []byte(seedConfig), 0644); err != nil {
		t.Fatalf("failed to write seed config: %v", err)
	}

	// 2. PUT /admin/agents/{name}/dlp (configure packs, overrides, and verify dlp.json emitted)
	cfg := policy.AgentPolicyConfig{
		AgentName: agentName,
		PackIDs:   []string{"pack:tr-kvkk"},
		Overrides: []policy.RuleOverride{
			{
				RuleID:  "rule:tr-tckn",
				Action:  policy.ActionBlock,
				Enabled: true,
			},
		},
		CustomPatterns: []policy.CustomPattern{
			{
				Name:   "VIP Ticket ID",
				Regex:  `\bVIP-[0-9]{4}\b`,
				Action: policy.ActionMask,
			},
		},
		ToolExemptions: map[string]policy.ToolExemption{
			"trusted_crm_lookup": {Request: true, Response: false},
		},
	}
	body, _ := json.Marshal(cfg)
	reqPut := httptest.NewRequest(http.MethodPut, "/admin/agents/"+agentName+"/dlp", bytes.NewReader(body))
	recPut := httptest.NewRecorder()
	handler.ServeHTTP(recPut, reqPut)

	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT agent dlp failed with %d: %s", recPut.Code, recPut.Body.String())
	}

	var putResp struct {
		Status   string                     `json:"status"`
		Compiled policy.CompiledAgentPolicy `json:"compiled"`
	}
	if err := json.Unmarshal(recPut.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode put response failed: %v", err)
	}
	if putResp.Status != "saved" {
		t.Errorf("expected status 'saved', got %s", putResp.Status)
	}
	if len(putResp.Compiled.EffectiveRules) == 0 {
		t.Errorf("expected compiled effective rules, got 0")
	}

	// 3. Verify dlp.json exists on disk
	expectedFile := filepath.Join(tempAgentsDir, agentName, "current", "dlp.json")
	if _, err := os.Stat(expectedFile); err != nil {
		t.Fatalf("expected emitted dlp.json at %s, but file not found: %v", expectedFile, err)
	}

	// 4. Verify snapshot archive was created prior to saving DLP
	reqArchives := httptest.NewRequest(http.MethodGet, "/admin/agents/archives?agent="+agentName, nil)
	recArchives := httptest.NewRecorder()
	handler.ServeHTTP(recArchives, reqArchives)
	if recArchives.Code != http.StatusOK {
		t.Fatalf("GET /admin/agents/archives failed: %d %s", recArchives.Code, recArchives.Body.String())
	}
	var archResp struct {
		Archives []string `json:"archives"`
	}
	if err := json.Unmarshal(recArchives.Body.Bytes(), &archResp); err != nil {
		t.Fatalf("decode archives failed: %v", err)
	}
	if len(archResp.Archives) != 1 {
		t.Fatalf("expected 1 archive snapshot after DLP save, got %d", len(archResp.Archives))
	}
	archivedConfigFile := filepath.Join(tempAgentsDir, agentName, "archive", archResp.Archives[0], "config.json")
	if _, err := os.Stat(archivedConfigFile); err != nil {
		t.Errorf("expected archived config.json at %s, got: %v", archivedConfigFile, err)
	}

	// 5. Subsequent DLP save creates another atomic rollback point containing dlp.json
	cfg.CustomPatterns = append(cfg.CustomPatterns, policy.CustomPattern{
		Name:   "Internal Secret",
		Regex:  `\bSECRET-[A-Z0-9]+\b`,
		Action: policy.ActionBlock,
	})
	body2, _ := json.Marshal(cfg)
	reqPut2 := httptest.NewRequest(http.MethodPut, "/admin/agents/"+agentName+"/dlp", bytes.NewReader(body2))
	recPut2 := httptest.NewRecorder()
	handler.ServeHTTP(recPut2, reqPut2)
	if recPut2.Code != http.StatusOK {
		t.Fatalf("second PUT agent dlp failed: %d %s", recPut2.Code, recPut2.Body.String())
	}

	recArchives2 := httptest.NewRecorder()
	handler.ServeHTTP(recArchives2, reqArchives)
	var archResp2 struct {
		Archives []string `json:"archives"`
	}
	if err := json.Unmarshal(recArchives2.Body.Bytes(), &archResp2); err != nil {
		t.Fatalf("decode archives2 failed: %v", err)
	}
	if len(archResp2.Archives) != 2 {
		t.Fatalf("expected 2 archive snapshots after second DLP save, got %d", len(archResp2.Archives))
	}
}

func TestPolicyPackHandlers_AgentDLP_ReconcileFromDisk(t *testing.T) {
	server, store, _, tempAgentsDir := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	agentName := "unreconciled-agent"
	currentDir := filepath.Join(tempAgentsDir, agentName, "current")
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		t.Fatalf("failed to create agent current dir: %v", err)
	}

	// Prepare an existing dlp.json with KVKK rules and tool exemption
	existingDLP := `{
		"enabled": true,
		"patterns": [
			{
				"name": "Turkey TCKN (Kimlik Numarası)",
				"regex": "\\b[1-9][0-9]{10}\\b",
				"action": "mask"
			},
			{
				"name": "Turkey IBAN",
				"regex": "\\bTR[0-9]{2}[0-9A-Z]{22}\\b",
				"action": "mask"
			},
			{
				"name": "Turkey Mobile Phone",
				"regex": "(?:\\+?90|0)?5[0-9]{2}[\\s\\-]?[0-9]{3}[\\s\\-]?[0-9]{2}[\\s\\-]?[0-9]{2}\\b",
				"action": "mask"
			},
			{
				"name": "Turkey Tax ID (VKN)",
				"regex": "\\b[0-9]{10}\\b",
				"action": "mask"
			}
		],
		"tool_exemptions": {
			"context7__resolve-library-id": {
				"request": true,
				"response": false
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(currentDir, "dlp.json"), []byte(existingDLP), 0644); err != nil {
		t.Fatalf("failed to write existing dlp.json: %v", err)
	}

	// Ensure DuckDB initially has NO record for this agent
	_, err := store.GetAgentConfig(context.Background(), agentName)
	if !errors.Is(err, policy.ErrConfigNotFound) {
		t.Fatalf("expected ErrConfigNotFound initially, got %v", err)
	}

	// Calling GET /admin/agents/{name}/dlp must automatically reconcile from disk
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/agents/"+agentName+"/dlp", nil)
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET agent dlp failed: %d %s", recGet.Code, recGet.Body.String())
	}

	var getResp struct {
		AgentName string                   `json:"agent_name"`
		Config    policy.AgentPolicyConfig `json:"config"`
		Compiled  *policy.CompiledAgentPolicy `json:"compiled"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode agent dlp response failed: %v", err)
	}

	// Verify pack:tr-kvkk was automatically attached
	foundKVKK := false
	for _, p := range getResp.Config.PackIDs {
		if p == "pack:tr-kvkk" {
			foundKVKK = true
			break
		}
	}
	if !foundKVKK {
		t.Errorf("expected pack:tr-kvkk to be attached during reconcile, got: %v", getResp.Config.PackIDs)
	}

	// Verify tool exemptions were preserved
	exempt, hasExempt := getResp.Config.ToolExemptions["context7__resolve-library-id"]
	if !hasExempt || !exempt.Request || exempt.Response {
		t.Errorf("expected context7 exemption preserved, got: %+v", getResp.Config.ToolExemptions)
	}

	// Verify DuckDB was updated
	saved, err := store.GetAgentConfig(context.Background(), agentName)
	if err != nil {
		t.Fatalf("expected config to be saved in DuckDB after reconcile, got err: %v", err)
	}
	if len(saved.PackIDs) == 0 {
		t.Errorf("saved DuckDB config has empty PackIDs")
	}

	// Verify compiled effective rules
	if getResp.Compiled == nil || len(getResp.Compiled.EffectiveRules) == 0 {
		t.Fatalf("expected compiled effective rules after reconcile, got none")
	}
}

func TestPolicyPackHandlers_Recommend(t *testing.T) {
	server, _, _, _ := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	reqBody := policy.RecommendationRequest{
		ProtocolNames: []string{"Postgres Primary DB"},
		ToolNames:     []string{"query", "list_tables"},
		AttachedPacks: []string{},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/admin/policy-packs/recommend", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/policy-packs/recommend failed with %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Recommendations []policy.Recommendation `json:"recommendations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode recommendation response failed: %v", err)
	}
	if len(resp.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(resp.Recommendations))
	}
	if resp.Recommendations[0].PackID != "pack:db-sanitization" {
		t.Errorf("expected pack:db-sanitization, got %s", resp.Recommendations[0].PackID)
	}
}

func TestPolicyPreviewEndpoint(t *testing.T) {
	server, _, _, _ := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	cfg := policy.AgentPolicyConfig{
		AgentName: "preview-test-agent",
		PackIDs:   []string{"pack:qa-qcb"},
		ToolExemptions: map[string]policy.ToolExemption{
			"qcb_query": {Request: true, Response: false},
		},
	}
	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest(http.MethodPost, "/admin/policies/preview", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/policies/preview failed with %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Status   string                     `json:"status"`
		Compiled policy.CompiledAgentPolicy `json:"compiled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview response failed: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
	if len(resp.Compiled.EffectiveRules) == 0 {
		t.Fatalf("expected effective rules to be populated from pack:qa-qcb")
	}
	if !resp.Compiled.ToolExemptions["qcb_query"].Request || resp.Compiled.ToolExemptions["qcb_query"].Response {
		t.Errorf("unexpected tool exemptions in preview response: %+v", resp.Compiled.ToolExemptions)
	}
}

func TestPolicyPreviewEndpoint_EdgeCases(t *testing.T) {
	server, _, _, _ := setupTestAdminServerWithPolicy(t)
	handler := server.Handler()

	// 1. Empty agent_name automatically defaults to "preview-agent" (clean developer ergonomics)
	cfgEmptyAgent := policy.AgentPolicyConfig{
		AgentName: "",
		PackIDs:   []string{"pack:qa-qcb"},
	}
	bodyEmpty, _ := json.Marshal(cfgEmptyAgent)
	req1 := httptest.NewRequest(http.MethodPost, "/admin/policies/preview", bytes.NewReader(bodyEmpty))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty agent_name defaulting to preview-agent, got %d", rec1.Code)
	}
	var resp1 struct {
		Compiled policy.CompiledAgentPolicy `json:"compiled"`
	}
	_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)
	if resp1.Compiled.AgentName != "preview-agent" {
		t.Errorf("expected Compiled.AgentName to default to 'preview-agent', got '%s'", resp1.Compiled.AgentName)
	}

	// 2. Invalid custom pattern regex -> 400 Bad Request
	cfgBadRegex := policy.AgentPolicyConfig{
		AgentName: "preview-regex-agent",
		CustomPatterns: []policy.CustomPattern{
			{Name: "bad_regex", Regex: "[unclosed_brace", Action: "mask"},
		},
	}
	bodyBadRegex, _ := json.Marshal(cfgBadRegex)
	req2 := httptest.NewRequest(http.MethodPost, "/admin/policies/preview", bytes.NewReader(bodyBadRegex))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid custom regex, got %d", rec2.Code)
	}

	// 3. Malformed JSON body -> 400 Bad Request
	reqMalformed := httptest.NewRequest(http.MethodPost, "/admin/policies/preview", bytes.NewReader([]byte(`{not a valid json`)))
	recMalformed := httptest.NewRecorder()
	handler.ServeHTTP(recMalformed, reqMalformed)
	if recMalformed.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed json, got %d", recMalformed.Code)
	}

	// 4. Method not allowed (GET instead of POST) -> 405
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/policies/preview", nil)
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", recGet.Code)
	}

	// 5. Alias endpoint /admin/policy-packs/preview works identically
	cfgValid := policy.AgentPolicyConfig{
		AgentName: "preview-alias-agent",
		PackIDs:   []string{"pack:qa-qcb"},
	}
	bodyValid, _ := json.Marshal(cfgValid)
	reqAlias := httptest.NewRequest(http.MethodPost, "/admin/policy-packs/preview", bytes.NewReader(bodyValid))
	recAlias := httptest.NewRecorder()
	handler.ServeHTTP(recAlias, reqAlias)
	if recAlias.Code != http.StatusOK {
		t.Errorf("expected 200 for alias /admin/policy-packs/preview, got %d", recAlias.Code)
	}
}

