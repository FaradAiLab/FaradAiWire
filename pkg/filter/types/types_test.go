package types

import (
	"context"
	"testing"
)

func TestContextHelpers_ToolName(t *testing.T) {
	// 1. Nil context should return empty string
	if GetToolName(nil) != "" {
		t.Errorf("expected empty string for nil context, got %q", GetToolName(nil))
	}

	// 2. Empty context without tool name should return empty string
	ctx := context.Background()
	if GetToolName(ctx) != "" {
		t.Errorf("expected empty string for context without tool name, got %q", GetToolName(ctx))
	}

	// 3. Context with tool name should return bound tool name
	tool := "execute_bash"
	boundCtx := WithToolName(ctx, tool)
	if GetToolName(boundCtx) != tool {
		t.Errorf("expected %q, got %q", tool, GetToolName(boundCtx))
	}

	// 4. Overwriting tool name should update it cleanly
	newTool := "read_file"
	updatedCtx := WithToolName(boundCtx, newTool)
	if GetToolName(updatedCtx) != newTool {
		t.Errorf("expected %q, got %q", newTool, GetToolName(updatedCtx))
	}
}

func TestContextHelpers_HumanApproved(t *testing.T) {
	if IsHumanApproved(nil) {
		t.Errorf("expected false for nil context")
	}

	ctx := context.Background()
	if IsHumanApproved(ctx) {
		t.Errorf("expected false for empty context")
	}

	approvedCtx := context.WithValue(ctx, HumanApprovedContextKey, true)
	if !IsHumanApproved(approvedCtx) {
		t.Errorf("expected true for approved context")
	}
}
