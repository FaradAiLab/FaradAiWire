package mcp_test

import (
	"encoding/json"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestProtocolPublicAPI(t *testing.T) {
	// 1. Test error creation
	errObj := mcp.NewError(mcp.ErrDLPViolation, "DLP blocked", map[string]string{"rule": "credit_card"})
	if errObj.Code != mcp.ErrDLPViolation {
		t.Errorf("expected code %d, got %d", mcp.ErrDLPViolation, errObj.Code)
	}
	if errStr := errObj.Error(); errStr == "" {
		t.Errorf("expected formatted error string")
	}

	// 2. Test response wrapper
	respObj := mcp.NewErrorResponse("req-1", mcp.ErrPrefillInjection, "Prefill blocked", nil)
	if respObj.JSONRPC != "2.0" {
		t.Errorf("expected JSON-RPC 2.0")
	}
	if respObj.Error.Code != mcp.ErrPrefillInjection {
		t.Errorf("expected code %d, got %d", mcp.ErrPrefillInjection, respObj.Error.Code)
	}

	// 3. Test parse request
	rawReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"},"meta":{"trace_id":"trc-123"}}`)
	req, resp, isReq, err := mcp.ParseMessage(rawReq)
	if err != nil {
		t.Fatalf("unexpected error parsing request: %v", err)
	}
	if !isReq || req == nil || resp != nil {
		t.Fatalf("expected request parsed successfully")
	}
	if req.ExtractTraceID() != "trc-123" {
		t.Errorf("expected trace id 'trc-123', got '%s'", req.ExtractTraceID())
	}
	if req.IsNotification() {
		t.Errorf("expected IsNotification to be false for call with id")
	}

	// 4. Test parse response
	rawResp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`)
	req2, resp2, isReq2, err2 := mcp.ParseMessage(rawResp)
	if err2 != nil {
		t.Fatalf("unexpected error parsing response: %v", err2)
	}
	if isReq2 || req2 != nil || resp2 == nil {
		t.Fatalf("expected response parsed successfully")
	}

	var resMap map[string]string
	if err := json.Unmarshal(resp2.Result, &resMap); err != nil || resMap["status"] != "ok" {
		t.Errorf("expected result status 'ok'")
	}
}
