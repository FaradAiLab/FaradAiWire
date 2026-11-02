package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// FallbackNotice is the in-band alert injected into tool responses when Semantic Guard is offline.
const FallbackNotice = "[🛡️ FaradAiWire: Semantic Guard offline, L1 regex fallback active]"

// NotificationSink defines the contract for sending MCP protocol notifications to the connected client.
type NotificationSink interface {
	SendNotification(ctx context.Context, method string, params interface{}) error
}

// NotificationFunc is a functional adapter for NotificationSink.
type NotificationFunc func(ctx context.Context, method string, params interface{}) error

func (f NotificationFunc) SendNotification(ctx context.Context, method string, params interface{}) error {
	return f(ctx, method, params)
}

func (f *GuardFilter) notifyDisconnection(ctx context.Context, toolName string) {
	f.mu.RLock()
	sink := f.notificationSink
	f.mu.RUnlock()

	if sink != nil {
		_ = sink.SendNotification(ctx, "notifications/message", map[string]interface{}{
			"level":  "warning",
			"logger": "faradai-guard",
			"data":   fmt.Sprintf("Semantic Security Guard is offline. L1 regex fallback active (tool: %s).", toolName),
		})
	}

	NotifyDarwin("FaradAiWire Security Alert", "Semantic Guard is offline; L1 regex fallback active.")
}

// AppendFallbackNotice safely appends the FallbackNotice to a JSON-encoded tool response
// without breaking valid JSON syntax. It handles MCP content objects, raw strings, and general objects.
func AppendFallbackNotice(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	// 1. Idempotency check: avoid double-appending
	if strings.Contains(string(raw), FallbackNotice) {
		return raw
	}

	// 2. Try parsing as standard JSON object (e.g. MCP tool result: {"content": [...], ...})
	var genericMap map[string]interface{}
	if err := json.Unmarshal(raw, &genericMap); err == nil {
		if contentRaw, hasContent := genericMap["content"]; hasContent {
			if contentSlice, ok := contentRaw.([]interface{}); ok && len(contentSlice) > 0 {
				appended := false
				for i := len(contentSlice) - 1; i >= 0; i-- {
					if itemMap, ok := contentSlice[i].(map[string]interface{}); ok {
						if itemMap["type"] == "text" {
							if textVal, ok := itemMap["text"].(string); ok {
								itemMap["text"] = textVal + "\n\n" + FallbackNotice
								appended = true
								break
							}
						}
					}
				}
				if !appended {
					contentSlice = append(contentSlice, map[string]interface{}{
						"type": "text",
						"text": FallbackNotice,
					})
					genericMap["content"] = contentSlice
				}
				if mutatedBytes, err := json.Marshal(genericMap); err == nil {
					return json.RawMessage(mutatedBytes)
				}
			} else if ok && len(contentSlice) == 0 {
				genericMap["content"] = []interface{}{
					map[string]interface{}{
						"type": "text",
						"text": FallbackNotice,
					},
				}
				if mutatedBytes, err := json.Marshal(genericMap); err == nil {
					return json.RawMessage(mutatedBytes)
				}
			}
		}

		// Generic JSON object without content array
		genericMap["_faradai_notice"] = FallbackNotice
		if mutatedBytes, err := json.Marshal(genericMap); err == nil {
			return json.RawMessage(mutatedBytes)
		}
	}

	// 3. Try parsing as JSON string (e.g. "output text")
	var strVal string
	if err := json.Unmarshal(raw, &strVal); err == nil {
		mutated := strVal + "\n\n" + FallbackNotice
		if mutatedBytes, err := json.Marshal(mutated); err == nil {
			return json.RawMessage(mutatedBytes)
		}
	}

	return raw
}

