// Package mcp implements the Model Context Protocol (MCP) and JSON-RPC 2.0 wire models,
// serialization helpers, standard protocol codes, and Farad Ai-specific security rejection error codes.
package mcp

import (
	"encoding/json"
	"fmt"
)

// Standard JSON-RPC 2.0 and MCP Error Codes
const (
	// ErrParseError indicates invalid JSON was received by the server (-32700).
	ErrParseError = -32700
	// ErrInvalidRequest indicates the JSON sent is not a valid Request object (-32600).
	ErrInvalidRequest = -32600
	// ErrMethodNotFound indicates the method does not exist or is not available (-32601).
	ErrMethodNotFound = -32601
	// ErrInvalidParams indicates invalid method parameter(s) (-32602).
	ErrInvalidParams = -32602
	// ErrInternalError indicates an internal JSON-RPC error (-32603).
	ErrInternalError = -32603

	// ErrPrefillInjection indicates assistant sockpuppeting / prefill injection detected (-32001).
	ErrPrefillInjection = -32001
	// ErrSchemaValidation indicates tool parameter schema validation failed (-32002).
	ErrSchemaValidation = -32002
	// ErrPolicyDenied indicates policy authorization denied (-32003).
	ErrPolicyDenied = -32003
	// ErrDLPViolation indicates sensitive data (PII/DLP) leakage blocked (-32004).
	ErrDLPViolation = -32004
	// ErrHITLDenied indicates human-in-the-loop approval denied or timed out (-32000).
	ErrHITLDenied = -32000
	// ErrIndirectInjection indicates indirect prompt injection detected in tool response (-32006).
	ErrIndirectInjection = -32006
	// ErrToolSchemaDrift indicates tool schema dynamic modification/poisoning detected (-32007).
	ErrToolSchemaDrift = -32007
	// ErrLoopDetected indicates an infinite loop detected in consecutive tool calls (-32008).
	ErrLoopDetected = -32008
	// ErrRateLimitExceeded indicates tool execution rate limit exceeded (-32009).
	ErrRateLimitExceeded = -32009
)

// Request represents a JSON-RPC 2.0 request or notification
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`   // Can be string, float64, or nil
	Meta    json.RawMessage `json:"meta,omitempty"` // Custom metadata (contains trace IDs, progress tokens, etc.)
}

// IsNotification returns true if the request is a notification (no ID)
func (r *Request) IsNotification() bool {
	return r.ID == nil
}

// ExtractTraceID retrieves a trace ID from the request meta object if present.
func (r *Request) ExtractTraceID() string {
	if len(r.Meta) == 0 {
		return ""
	}
	var metaMap map[string]interface{}
	if err := json.Unmarshal(r.Meta, &metaMap); err == nil {
		for _, key := range []string{"trace_id", "traceId", "x-trace-id", "x_trace_id", "trace"} {
			if val, ok := metaMap[key]; ok {
				if strVal, ok := val.(string); ok {
					return strVal
				}
			}
		}
	}
	return ""
}

// Response represents a JSON-RPC 2.0 response
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// Error represents a JSON-RPC 2.0 error object
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Error returns the formatted JSON-RPC error string satisfying the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error: code %d, message: %s", e.Code, e.Message)
}

// NewError creates a structured MCP Error
func NewError(code int, message string, data interface{}) *Error {
	var rawData json.RawMessage
	if data != nil {
		if d, err := json.Marshal(data); err == nil {
			rawData = d
		}
	}
	return &Error{
		Code:    code,
		Message: message,
		Data:    rawData,
	}
}

// NewErrorResponse creates a full JSON-RPC response wrapping an error
func NewErrorResponse(id interface{}, code int, message string, data interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		Error:   NewError(code, message, data),
		ID:      id,
	}
}

type rawMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  *string         `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Meta    json.RawMessage `json:"meta,omitempty"`
}

// ParseMessage parses a raw JSON byte slice into either a Request or Response in a single pass.
// Returns (request, response, isRequest, error)
func ParseMessage(data []byte) (*Request, *Response, bool, error) {
	var raw rawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, false, err
	}

	if raw.JSONRPC != "2.0" {
		return nil, nil, false, fmt.Errorf("invalid JSON-RPC version: %s", raw.JSONRPC)
	}

	if raw.Method != nil {
		req := &Request{
			JSONRPC: raw.JSONRPC,
			Method:  *raw.Method,
			Params:  raw.Params,
			ID:      raw.ID,
			Meta:    raw.Meta,
		}
		return req, nil, true, nil
	}

	resp := &Response{
		JSONRPC: raw.JSONRPC,
		Result:  raw.Result,
		Error:   raw.Error,
		ID:      raw.ID,
	}
	return nil, resp, false, nil
}
