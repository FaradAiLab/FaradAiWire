package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestContextHandler_AttachesContextFields(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	log := slog.New(NewContextHandler(base)).With(slog.String("component", "proxy"))

	ctx := context.Background()
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-xyz")
	ctx = context.WithValue(ctx, filter.InvocationIDContextKey, "inv-123")
	ctx = context.WithValue(ctx, filter.AgentNameContextKey, "agent-alpha")

	log.InfoContext(ctx, "hello trace")

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to unmarshal JSON log: %v (raw=%s)", err, buf.String())
	}

	if decoded["trace_id"] != "trace-xyz" {
		t.Errorf("expected top-level trace_id=trace-xyz, got %v (raw=%s)", decoded["trace_id"], buf.String())
	}
	if decoded["invocation_id"] != "inv-123" {
		t.Errorf("expected top-level invocation_id=inv-123, got %v", decoded["invocation_id"])
	}
	if decoded["agent_name"] != "agent-alpha" {
		t.Errorf("expected top-level agent_name=agent-alpha, got %v", decoded["agent_name"])
	}
	if decoded["component"] != "proxy" {
		t.Errorf("expected component=proxy preserved, got %v", decoded["component"])
	}

	// Verify WithGroup continues preserving groups cleanly
	buf.Reset()
	log.WithGroup("http").InfoContext(ctx, "grouped msg", slog.String("method", "POST"))
	var grouped map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &grouped); err != nil {
		t.Fatalf("unmarshal grouped: %v", err)
	}
	httpGroup, ok := grouped["http"].(map[string]interface{})
	if !ok || httpGroup["method"] != "POST" || httpGroup["trace_id"] != "trace-xyz" {
		t.Errorf("expected grouped http fields and trace_id, got %#v", grouped)
	}
}

func TestContextHandler_OmitsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewContextHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	log.InfoContext(context.Background(), "plain message")

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"trace_id", "invocation_id", "agent_name"} {
		if _, exists := decoded[key]; exists {
			t.Errorf("did not expect %s when absent from ctx", key)
		}
	}
}
