package filter_test

import (
	"context"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type customFilter struct {
	filter.BaseSecurityFilter
}

func (c *customFilter) Name() string { return "custom" }
func (c *customFilter) Order() int    { return filter.OrderDLP }

func TestFilterPublicAPI(t *testing.T) {
	// Verify strict order hierarchy
	if filter.OrderPrefill >= filter.OrderRateLimit {
		t.Errorf("expected OrderPrefill < OrderRateLimit")
	}
	if filter.OrderRateLimit >= filter.OrderLoopProtection {
		t.Errorf("expected OrderRateLimit < OrderLoopProtection")
	}
	if filter.OrderLoopProtection >= filter.OrderPolicy {
		t.Errorf("expected OrderLoopProtection < OrderPolicy")
	}
	if filter.OrderPolicy >= filter.OrderSchemaValidation {
		t.Errorf("expected OrderPolicy < OrderSchemaValidation")
	}
	if filter.OrderSchemaValidation >= filter.OrderDLP {
		t.Errorf("expected OrderSchemaValidation < OrderDLP")
	}
	if filter.OrderDLP >= filter.OrderInjectionScanner {
		t.Errorf("expected OrderDLP < OrderInjectionScanner")
	}
	if filter.OrderInjectionScanner >= filter.OrderHITL {
		t.Errorf("expected OrderInjectionScanner < OrderHITL")
	}

	// Verify BaseSecurityFilter pass-through behavior
	f := &customFilter{}
	if f.Name() != "custom" {
		t.Errorf("expected custom filter name")
	}
	if f.Order() != filter.OrderDLP {
		t.Errorf("expected order %d, got %d", filter.OrderDLP, f.Order())
	}

	ctx := context.Background()
	req := &mcp.Request{JSONRPC: "2.0", Method: "tools/call"}
	resp, err := f.ExecuteRequest(ctx, req)
	if err != nil || resp != nil {
		t.Errorf("expected BaseSecurityFilter.ExecuteRequest to return nil, nil")
	}

	outResp := &mcp.Response{JSONRPC: "2.0"}
	res, err := f.ExecuteResponse(ctx, outResp)
	if err != nil || res != outResp {
		t.Errorf("expected BaseSecurityFilter.ExecuteResponse to pass through response")
	}
}
