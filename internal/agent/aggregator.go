package agent

import (
	"context"
	"fmt"
	"strings"
)

// ManifestAggregator compiles and normalizes agent tool manifests for MCP tools/list responses.
type ManifestAggregator interface {
	CompileToolsList(ctx context.Context, agentName string) ([]map[string]interface{}, error)
}

// DefaultManifestAggregator implements ManifestAggregator using an agent.Resolver.
type DefaultManifestAggregator struct {
	repo Resolver
}

// NewManifestAggregator creates a new DefaultManifestAggregator.
func NewManifestAggregator(repo Resolver) *DefaultManifestAggregator {
	return &DefaultManifestAggregator{repo: repo}
}

// CompileToolsList retrieves the tools manifest for the specified agent (falling back to default agent if empty)
// and returns normalized JSON-RPC tools list schema objects.
func (a *DefaultManifestAggregator) CompileToolsList(ctx context.Context, agentName string) ([]map[string]interface{}, error) {
	if a.repo == nil {
		return nil, fmt.Errorf("agent repository is not configured")
	}

	targetAgent := agentName
	if targetAgent == "" {
		if defAgent, err := a.repo.GetDefaultAgent(); err == nil && defAgent != nil {
			targetAgent = defAgent.AgentName
		}
	}

	if targetAgent == "" {
		return nil, ErrAgentNotFound
	}

	manifest, err := a.repo.GetAgentManifest(targetAgent)
	if err != nil {
		return nil, err
	}

	agentCfg, _ := a.repo.GetAgentConfig(targetAgent)
	if agentCfg != nil {
		manifest = agentCfg.ComputeEffectiveTools(manifest)
	}

	isAggregated := true
	if agentCfg != nil {
		isAggregated = agentCfg.IsAggregated()
	}

	toolsList := make([]map[string]interface{}, 0, len(manifest))
	for _, t := range manifest {
		rawName := t.RawName
		if rawName == "" {
			if strings.Contains(t.Name, "__") {
				parts := strings.SplitN(t.Name, "__", 2)
				rawName = parts[1]
			} else {
				rawName = t.Name
			}
		}

		toolName := rawName
		if isAggregated {
			protoSlug := ""
			if agentCfg != nil {
				proto := agentCfg.FindProtocol(t.ProtocolID)
				if proto == nil {
					proto = agentCfg.FindProtocol(t.ProtocolName)
				}
				if proto != nil {
					protoSlug = GetProtocolSlug(proto)
				}
			}
			if protoSlug == "" {
				if t.ProtocolID != "" && !strings.Contains(t.ProtocolID, " ") {
					protoSlug = strings.ToLower(t.ProtocolID)
				} else if t.ProtocolName != "" {
					protoSlug = strings.ToLower(strings.ReplaceAll(t.ProtocolName, " ", "_"))
				}
			}

			if protoSlug != "" {
				cleanRaw := strings.TrimPrefix(rawName, protoSlug+"__")
				toolName = fmt.Sprintf("%s__%s", protoSlug, cleanRaw)
			}
		}

		toolMap := map[string]interface{}{
			"name": toolName,
		}
		if t.Description != "" {
			toolMap["description"] = t.Description
		}
		if t.InputSchema != nil {
			toolMap["inputSchema"] = t.InputSchema
		} else {
			toolMap["inputSchema"] = map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			}
		}
		toolsList = append(toolsList, toolMap)
	}

	return toolsList, nil
}
