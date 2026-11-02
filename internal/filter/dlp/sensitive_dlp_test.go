package dlp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestSensitiveDLP_DefaultBaselinePatterns(t *testing.T) {
	patterns := DefaultBaselinePatterns()
	if len(patterns) == 0 {
		t.Fatal("DefaultBaselinePatterns returned empty slice")
	}

	names := make(map[string]bool)
	for _, p := range patterns {
		if p.Name == "" {
			t.Error("Pattern has empty name")
		}
		if p.Regex == "" {
			t.Errorf("Pattern %s has empty regex", p.Name)
		}
		if p.Action != "block" && p.Action != "mask" {
			t.Errorf("Pattern %s has invalid action %s", p.Name, p.Action)
		}
		names[p.Name] = true
	}

	for _, expected := range []string{"private_keys", "sensitive_files", "aws_credentials"} {
		if !names[expected] {
			t.Errorf("Expected baseline pattern %q not found in DefaultBaselinePatterns", expected)
		}
	}
}

func TestSensitiveDLP_ToolParameters_BlockingMatrix(t *testing.T) {
	filter, err := NewDLPFilter(true, nil, DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to create DLP filter with baseline patterns: %v", err)
	}

	tests := []struct {
		name         string
		paramsJSON   string
		expectedRule string
	}{
		// Sensitive environment variable files
		{
			name:         ".env file direct",
			paramsJSON:   `{"path": ".env"}`,
			expectedRule: "sensitive_files",
		},
		{
			name:         ".env.local file",
			paramsJSON:   `{"file": "/workspace/project/.env.local"}`,
			expectedRule: "sensitive_files",
		},
		{
			name:         ".env.production in nested path",
			paramsJSON:   `{"command": "cat /var/www/.env.production"}`,
			expectedRule: "sensitive_files",
		},
		// SSH and private key files
		{
			name:         "id_rsa filename",
			paramsJSON:   `{"filename": "id_rsa"}`,
			expectedRule: "sensitive_files",
		},
		{
			name:         "id_rsa full path",
			paramsJSON:   `{"path": "/home/user/.ssh/id_rsa"}`,
			expectedRule: "sensitive_files",
		},
		{
			name:         "id_ed25519 full path",
			paramsJSON:   `{"path": "~/.ssh/id_ed25519"}`,
			expectedRule: "sensitive_files",
		},
		// Cloud credential store files
		{
			name:         "aws credentials file",
			paramsJSON:   `{"filepath": "/home/user/.aws/credentials"}`,
			expectedRule: "sensitive_files",
		},
		// System authentication files
		{
			name:         "/etc/shadow access",
			paramsJSON:   `{"target": "/etc/shadow"}`,
			expectedRule: "sensitive_files",
		},
		{
			name:         "/etc/passwd access",
			paramsJSON:   `{"target": "/etc/passwd"}`,
			expectedRule: "sensitive_files",
		},
		// Raw private key headers in parameters
		{
			name:         "PEM RSA private key",
			paramsJSON:   `{"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."}`,
			expectedRule: "private_keys",
		},
		{
			name:         "PEM EC private key",
			paramsJSON:   `{"key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI..."}`,
			expectedRule: "private_keys",
		},
		{
			name:         "PEM OPENSSH private key",
			paramsJSON:   `{"key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza..."}`,
			expectedRule: "private_keys",
		},
		{
			name:         "PEM DSA private key",
			paramsJSON:   `{"key": "-----BEGIN DSA PRIVATE KEY-----\nMIIBvAIBAAK..."}`,
			expectedRule: "private_keys",
		},
		{
			name:         "PEM PGP private key",
			paramsJSON:   `{"key": "-----BEGIN PGP PRIVATE KEY-----\nmQENBF6..."}`,
			expectedRule: "private_keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mcp.Request{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params:  json.RawMessage(tt.paramsJSON),
			}

			_, mcpErr := filter.FilterRequest(context.Background(), req)
			if mcpErr == nil {
				t.Fatalf("Expected tool parameter %q to be blocked, but was allowed", tt.paramsJSON)
			}

			if mcpErr.Code != mcp.ErrDLPViolation {
				t.Errorf("Expected error code %d (ErrDLPViolation), got %d", mcp.ErrDLPViolation, mcpErr.Code)
			}

			if !strings.Contains(mcpErr.Message, tt.expectedRule) {
				t.Errorf("Expected error message to mention rule %q, got: %s", tt.expectedRule, mcpErr.Message)
			}
		})
	}
}

func TestSensitiveDLP_SafeParameters_Allowed(t *testing.T) {
	filter, err := NewDLPFilter(true, nil, DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	safeParams := []string{
		`{"path": "/home/user/documents/report.pdf"}`,
		`{"file": "public_key.pub"}`,
		`{"ssh_pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePublicKey user@host"}`,
		`{"query": "select count(*) from users"}`,
		`{"env": "production", "region": "us-east-1"}`,
	}

	for _, paramJSON := range safeParams {
		req := &mcp.Request{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params:  json.RawMessage(paramJSON),
		}

		filteredReq, mcpErr := filter.FilterRequest(context.Background(), req)
		if mcpErr != nil {
			t.Fatalf("Expected safe parameter %s to be allowed, but got error: %v", paramJSON, mcpErr)
		}
		if string(filteredReq.Params) != paramJSON {
			t.Errorf("Expected unmodified params, got: %s", string(filteredReq.Params))
		}
	}
}

func TestSensitiveDLP_ToolOutputs_MaskingMatrix(t *testing.T) {
	filter, err := NewDLPFilter(true, nil, DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	tests := []struct {
		name          string
		rawResult     string
		sensitivePart string
	}{
		{
			name:          "AWS secret key in .env format",
			rawResult:     `{"content": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			sensitivePart: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			name:          "AWS access key ID with no spaces",
			rawResult:     `{"content": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}`,
			sensitivePart: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:          "AWS credentials in JSON format",
			rawResult:     `{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			sensitivePart: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			name:          "AWS credentials uppercase with colon",
			rawResult:     `{"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			sensitivePart: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &mcp.Response{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(tt.rawResult),
			}

			filteredResp, mcpErr := filter.FilterResponse(context.Background(), resp)
			if mcpErr != nil {
				t.Fatalf("FilterResponse returned unexpected error for masking rule: %v", mcpErr)
			}

			outputStr := string(filteredResp.Result)

			// Ensure sensitive part is redacted
			if strings.Contains(outputStr, tt.sensitivePart) {
				t.Fatalf("Sensitive credential leaked in output! Got: %s", outputStr)
			}

			// Ensure semantic placeholder [REDACTED:AWS_CREDENTIALS] was inserted
			expectedPlaceholder := "[REDACTED:AWS_CREDENTIALS]"
			if !strings.Contains(outputStr, expectedPlaceholder) {
				t.Fatalf("Expected output to contain %s, got: %s", expectedPlaceholder, outputStr)
			}
		})
	}
}

func TestSensitiveDLP_ToolOutputs_BlockingMatrix(t *testing.T) {
	filter, err := NewDLPFilter(true, nil, DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	tests := []struct {
		name       string
		rawResult  string
		ruleName   string
	}{
		{
			name:      "Tool output leaking RSA private key",
			rawResult: `{"content": "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."}`,
			ruleName:  "private_keys",
		},
		{
			name:      "Tool output leaking OPENSSH private key",
			rawResult: `{"content": "Dump:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."}`,
			ruleName:  "private_keys",
		},
		{
			name:      "Tool output leaking /etc/shadow file contents path",
			rawResult: `{"error": "Failed to read /etc/shadow: permission denied"}`,
			ruleName:  "sensitive_files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &mcp.Response{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(tt.rawResult),
			}

			_, mcpErr := filter.FilterResponse(context.Background(), resp)
			if mcpErr == nil {
				t.Fatalf("Expected output with %s to be blocked, but was allowed", tt.ruleName)
			}

			if mcpErr.Code != mcp.ErrDLPViolation {
				t.Errorf("Expected code %d, got %d", mcp.ErrDLPViolation, mcpErr.Code)
			}

			if !strings.Contains(mcpErr.Message, tt.ruleName) {
				t.Errorf("Expected message to contain %q, got: %s", tt.ruleName, mcpErr.Message)
			}
		})
	}
}

func TestSensitiveDLP_Collision_BlockPrecedenceOverMask(t *testing.T) {
	filter, err := NewDLPFilter(true, nil, DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	// Payload contains BOTH a mask target (aws_secret_access_key) and a block target (id_rsa)
	collisionPayload := `{"creds": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "target": "/home/user/.ssh/id_rsa"}`

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(collisionPayload),
	}

	_, mcpErr := filter.FilterRequest(context.Background(), req)
	if mcpErr == nil {
		t.Fatal("Expected block precedence on collision, but request was allowed")
	}

	if mcpErr.Code != mcp.ErrDLPViolation {
		t.Errorf("Expected ErrDLPViolation (-32004), got %d", mcpErr.Code)
	}

	if !strings.Contains(mcpErr.Message, "sensitive_files") {
		t.Errorf("Expected block rule 'sensitive_files' to take precedence, got: %s", mcpErr.Message)
	}
}
