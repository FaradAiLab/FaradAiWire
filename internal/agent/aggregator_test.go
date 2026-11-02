package agent

import (
	"context"
	"testing"
)

type mockAggregatorRepo struct {
	configs   map[string]*RouteConfig
	manifests map[string][]ToolMetadata
}

func (m *mockAggregatorRepo) GetAgentConfig(agentName string) (*RouteConfig, error) {
	if cfg, ok := m.configs[agentName]; ok {
		return cfg, nil
	}
	return nil, NewAgentNotFoundError(agentName)
}

func (m *mockAggregatorRepo) GetAgentManifest(agentName string) ([]ToolMetadata, error) {
	if man, ok := m.manifests[agentName]; ok {
		return man, nil
	}
	return nil, ErrManifestNotFound
}

func (m *mockAggregatorRepo) ResolveToolProtocol(agentName, toolName string) (*ToolTargetInfo, error) {
	return nil, nil
}

func (m *mockAggregatorRepo) ResolveTargetURLFromPath(path string, defaultTargetURL string) (string, error) {
	return defaultTargetURL, nil
}

func (m *mockAggregatorRepo) ListAgents() ([]string, error) {
	var list []string
	for k := range m.configs {
		list = append(list, k)
	}
	return list, nil
}

func (m *mockAggregatorRepo) GetDefaultAgent() (*RouteConfig, error) {
	if def, ok := m.configs["default"]; ok {
		return def, nil
	}
	for _, cfg := range m.configs {
		return cfg, nil
	}
	return nil, NewAgentNotFoundError("default")
}

func (m *mockAggregatorRepo) ClearCache() {}

func (m *mockAggregatorRepo) SaveAgentConfig(agentName string, cfg *RouteConfig) error { return nil }
func (m *mockAggregatorRepo) DeleteAgent(agentName string) error { return nil }
func (m *mockAggregatorRepo) SaveAgentManifest(agentName string, tools interface{}) error { return nil }
func (m *mockAggregatorRepo) ListAgentArchives(agentName string) ([]string, error) { return nil, nil }
func (m *mockAggregatorRepo) RollbackAgent(agentName, timestamp string) error { return nil }
func (m *mockAggregatorRepo) ArchiveAgentCurrent(agentName string) error { return nil }

func TestManifestAggregator_CompileToolsList_ExplicitAgent(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs: map[string]*RouteConfig{
			"sec-agent": {AgentName: "sec-agent"},
		},
		manifests: map[string][]ToolMetadata{
			"sec-agent": {
				{
					Name:        "port_scan",
					Description: "Scans network ports",
					InputSchema: map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"target": map[string]interface{}{"type": "string"},
						},
					},
				},
				{
					Name: "simple_ping",
					// Nil InputSchema and empty description to test defaults
				},
			},
		},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	tools, err := aggregator.CompileToolsList(ctx, "sec-agent")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// Tool 1
	if tools[0]["name"] != "port_scan" {
		t.Errorf("expected tool name 'port_scan', got '%v'", tools[0]["name"])
	}
	if tools[0]["description"] != "Scans network ports" {
		t.Errorf("unexpected description: %v", tools[0]["description"])
	}
	if tools[0]["inputSchema"] == nil {
		t.Errorf("expected non-nil inputSchema")
	}

	// Tool 2 - default schema
	if tools[1]["name"] != "simple_ping" {
		t.Errorf("expected tool name 'simple_ping', got '%v'", tools[1]["name"])
	}
	schema, ok := tools[1]["inputSchema"].(map[string]interface{})
	if !ok || schema["type"] != "object" {
		t.Errorf("expected default object schema, got: %+v", tools[1]["inputSchema"])
	}
}

func TestManifestAggregator_CompileToolsList_DefaultFallback(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs: map[string]*RouteConfig{
			"default": {AgentName: "default"},
		},
		manifests: map[string][]ToolMetadata{
			"default": {
				{Name: "def_tool"},
			},
		},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	// Empty agent name should resolve to default agent
	tools, err := aggregator.CompileToolsList(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 1 || tools[0]["name"] != "def_tool" {
		t.Fatalf("expected def_tool, got: %+v", tools)
	}
}

func TestManifestAggregator_CompileToolsList_AgentNotFound(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs:   map[string]*RouteConfig{},
		manifests: map[string][]ToolMetadata{},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	_, err := aggregator.CompileToolsList(ctx, "non-existent")
	if err == nil {
		t.Fatal("expected error for non-existent agent, got nil")
	}
}

func TestManifestAggregator_NilRepository(t *testing.T) {
	aggregator := NewManifestAggregator(nil)
	ctx := context.Background()

	_, err := aggregator.CompileToolsList(ctx, "any")
	if err == nil {
		t.Fatal("expected error when repo is nil, got nil")
	}
}

func TestManifestAggregator_AllowedToolsWhitelist(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs: map[string]*RouteConfig{
			"agent-whitelisted": {
				AgentName: "agent-whitelisted",
				Protocols: []ProtocolConfig{
					{
						ID:           "github-proto",
						Name:         "github",
						Type:         "stdio",
						Command:      "npx",
						AllowedTools: []string{"create_issue", "read_file"},
					},
					{
						ID:      "slack-proto",
						Name:    "slack",
						Type:    "sse",
						URLOrCommand: "https://mcp.slack.internal",
						// No AllowedTools: all tools permitted
					},
				},
			},
		},
		manifests: map[string][]ToolMetadata{
			"agent-whitelisted": {
				{
					Name:         "github__create_issue",
					ProtocolName: "github",
					Description:  "Create GitHub issue",
				},
				{
					Name:         "github__delete_repository",
					ProtocolName: "github",
					Description:  "Destructive repo delete",
				},
				{
					Name:         "github__read_file",
					ProtocolName: "github",
					Description:  "Read repo file",
				},
				{
					Name:         "slack__post_message",
					ProtocolName: "slack",
					Description:  "Post message to Slack",
				},
			},
		},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	tools, err := aggregator.CompileToolsList(ctx, "agent-whitelisted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// github__delete_repository must be omitted by the whitelist!
	// Expected: github__create_issue, github__read_file, slack__post_message
	if len(tools) != 3 {
		t.Fatalf("expected 3 permitted tools, got %d: %+v", len(tools), tools)
	}

	for _, tool := range tools {
		name := tool["name"].(string)
		if name == "github__delete_repository" {
			t.Errorf("unapproved tool 'github__delete_repository' was NOT filtered out by whitelist!")
		}
	}
}

func TestManifestAggregator_CompileToolsList_AggregatedNamespacing(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs: map[string]*RouteConfig{
			"agent-aggregated": {
				AgentName:   "agent-aggregated",
				RoutingMode: "aggregated",
				Protocols: []ProtocolConfig{
					{
						ID:   "context7",
						Name: "Context7 Live Docs & Code Context",
						Type: "http",
					},
					{
						ID:   "tavily",
						Name: "Tavily AI Search",
						Type: "sse",
					},
				},
			},
		},
		manifests: map[string][]ToolMetadata{
			"agent-aggregated": {
				{
					Name:         "resolve-library-id",
					RawName:      "resolve-library-id",
					ProtocolID:   "context7",
					ProtocolName: "Context7 Live Docs & Code Context",
				},
				{
					Name:         "query-docs",
					RawName:      "query-docs",
					ProtocolID:   "context7",
					ProtocolName: "Context7 Live Docs & Code Context",
				},
				{
					Name:         "tavily_search",
					RawName:      "tavily_search",
					ProtocolID:   "tavily",
					ProtocolName: "Tavily AI Search",
				},
			},
		},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	tools, err := aggregator.CompileToolsList(ctx, "agent-aggregated")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	expectedNames := map[string]bool{
		"context7__resolve-library-id": false,
		"context7__query-docs":         false,
		"tavily__tavily_search":        false,
	}

	for _, tool := range tools {
		name := tool["name"].(string)
		if _, exists := expectedNames[name]; exists {
			expectedNames[name] = true
		} else {
			t.Errorf("unexpected tool name in aggregated tools/list: %s", name)
		}
	}

	for expected, found := range expectedNames {
		if !found {
			t.Errorf("expected namespaced tool '%s' was not found in output", expected)
		}
	}
}

func TestManifestAggregator_CompileToolsList_DirectRoutingMode(t *testing.T) {
	repo := &mockAggregatorRepo{
		configs: map[string]*RouteConfig{
			"agent-direct": {
				AgentName:   "agent-direct",
				RoutingMode: "direct",
				Protocols: []ProtocolConfig{
					{
						ID:   "context7",
						Name: "Context7 Live Docs & Code Context",
						Type: "http",
					},
				},
			},
		},
		manifests: map[string][]ToolMetadata{
			"agent-direct": {
				{
					Name:         "context7__resolve-library-id",
					RawName:      "resolve-library-id",
					ProtocolID:   "context7",
					ProtocolName: "Context7 Live Docs & Code Context",
				},
			},
		},
	}

	aggregator := NewManifestAggregator(repo)
	ctx := context.Background()

	tools, err := aggregator.CompileToolsList(ctx, "agent-direct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	if tools[0]["name"] != "resolve-library-id" {
		t.Errorf("expected raw unprefixed name 'resolve-library-id' in direct mode, got '%v'", tools[0]["name"])
	}
}


