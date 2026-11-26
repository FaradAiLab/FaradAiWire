package mcpexport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestZeroLeakRedactor_AllSurfaces(t *testing.T) {
	secrets := []string{
		"ghp_super_secret_token_987654",
		"postgres_password_xyz123",
		"cookie_session_secret_abc",
		"x_api_key_secret_555",
		"query_secret_token_999",
		"cli_arg_secret_777",
		"fallback_default_secret_444",
	}

	env, envWarns := RedactEnv([]string{
		"NODE_ENV=production",
		"GITHUB_TOKEN=" + secrets[0],
		"DATABASE_URL=postgres://admin:" + secrets[1] + "@db.internal:5432/app",
		"EMPTY_SECRET_VAR=",
		"MALFORMED_LINE",
		"CUSTOM_REF=${env:MY_VAR:-" + secrets[6] + "}",
	}, ClientCursor, "github")

	if env["NODE_ENV"] != "production" {
		t.Fatalf("expected non-secret env preserved, got %q", env["NODE_ENV"])
	}
	if env["GITHUB_TOKEN"] != "[GITHUB_TOKEN]" {
		t.Fatalf("expected [GITHUB_TOKEN], got %q", env["GITHUB_TOKEN"])
	}
	if env["DATABASE_URL"] != "[DATABASE_URL]" {
		t.Fatalf("expected [DATABASE_URL], got %q", env["DATABASE_URL"])
	}
	if env["EMPTY_SECRET_VAR"] != "[EMPTY_SECRET_VAR]" {
		t.Fatalf("expected non-empty placeholder for Antigravity trap, got %q", env["EMPTY_SECRET_VAR"])
	}
	if env["CUSTOM_REF"] != "${env:MY_VAR}" {
		t.Fatalf("expected stripped default and no double-wrap, got %q", env["CUSTOM_REF"])
	}
	if len(envWarns) == 0 {
		t.Fatalf("expected malformed and default-stripped warnings")
	}

	headers, _ := RedactHeaders("github", "Bearer "+secrets[0], map[string]string{
		"Cookie":                 "sid=" + secrets[2],
		"X-API-Key":              secrets[3],
		"X-FaradAiWire-Internal": "drop-me",
		"Proxy-Authorization":    "Basic abc",
		"X-Custom-Mode":          "readonly",
	}, ClientClaudeCode)

	if headers["Authorization"] != "Bearer [GITHUB_API_KEY]" {
		t.Fatalf("unexpected Authorization: %q", headers["Authorization"])
	}
	if headers["Cookie"] != "[COOKIE]" || headers["X-API-Key"] != "[X_API_KEY]" {
		t.Fatalf("unexpected secret headers: %#v", headers)
	}
	if _, ok := headers["X-FaradAiWire-Internal"]; ok {
		t.Fatalf("blocked internal header leaked into export")
	}
	if _, ok := headers["Proxy-Authorization"]; ok {
		t.Fatalf("blocked hop-by-hop header leaked into export")
	}
	if headers["X-Custom-Mode"] != "readonly" {
		t.Fatalf("expected non-secret header preserved, got %q", headers["X-Custom-Mode"])
	}

	redURL, _ := RedactURL("https://alice:"+secrets[1]+"@mcp.example.com/sse?token="+secrets[4]+"&region=eu", ClientWindsurf, "github")
	if redURL != "https://[USERNAME]:[PASSWORD]@mcp.example.com/sse?token=[TOKEN]&region=eu" {
		t.Fatalf("unexpected redacted URL: %q", redURL)
	}

	args, _ := RedactArgs([]string{
		"--token=" + secrets[5],
		"--api-key", secrets[5],
		"postgres://user:" + secrets[1] + "@host/db",
	}, ClientClaudeDesktop, "github")
	if args[0] != "--token=[TOKEN]" || args[2] != "[API_KEY]" || args[3] != "postgres://[USERNAME]:[PASSWORD]@host/db" {
		t.Fatalf("unexpected redacted args: %#v", args)
	}

	blob, err := json.Marshal(map[string]any{
		"env":     env,
		"headers": headers,
		"url":     redURL,
		"args":    args,
	})
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	out := string(blob)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("raw secret %q leaked in output: %s", s, out)
		}
	}
	if strings.Contains(out, "••••••") || strings.Contains(out, "xxxxx") {
		t.Fatalf("legacy mask token leaked in output: %s", out)
	}
}

func TestRedactHeaders_CaseInsensitivePrecedence(t *testing.T) {
	headers, _ := RedactHeaders("svc", "raw-token-should-not-override", map[string]string{
		"authorization": "",
	}, ClientClaudeCode)
	if v, ok := headers["authorization"]; !ok || v != "" {
		t.Fatalf("expected explicit empty authorization precedence, got (%q, %v)", v, ok)
	}
	if _, hasUpper := headers["Authorization"]; hasUpper {
		t.Fatalf("unexpected duplicate Authorization header key: %#v", headers)
	}
}

func TestZeroLeakRedactor_MixedEnvRefsHeadersArgsAndURL(t *testing.T) {
	mixedSecrets := []string{
		"REAL_MIXED_DB_PASS",
		"sk_live_mixed_env_prefix",
		"bearer_tail_leak_999",
		"basic_literal_pass_888",
		"cli_hdr_bearer_secret",
		"cli_xapi_secret_123",
		"q_xapi_secret_456",
		"q_auth_tok_789",
		"frag_access_secret_321",
	}

	env, _ := RedactEnv([]string{
		"DATABASE_URL=postgres://admin:" + mixedSecrets[0] + "@${DB_HOST}:5432/prod",
		"API_KEY=" + mixedSecrets[1] + "${ENV_SUFFIX}",
		"PURE_ENV_DSN=postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:5432/prod",
	}, ClientCursor, "github")

	if env["DATABASE_URL"] != "postgres://[USERNAME]:[PASSWORD]@${env:DB_HOST}:5432/prod" {
		t.Fatalf("unexpected mixed DSN env redaction: %q", env["DATABASE_URL"])
	}
	if env["API_KEY"] != "[API_KEY]" {
		t.Fatalf("expected mixed API_KEY redacted to [API_KEY], got %q", env["API_KEY"])
	}
	if env["PURE_ENV_DSN"] != "postgres://${env:DB_USER}:${env:DB_PASS}@${env:DB_HOST}:5432/prod" {
		t.Fatalf("expected pure env DSN preserved for cursor, got %q", env["PURE_ENV_DSN"])
	}

	headers, _ := RedactHeaders("github", "", map[string]string{
		"Authorization": "Bearer ${TOKEN} " + mixedSecrets[2],
		"X-API-Key":     mixedSecrets[1] + "${SUFFIX}",
	}, ClientClaudeCode)
	if headers["Authorization"] != "Bearer [GITHUB_API_KEY]" {
		t.Fatalf("expected mixed Bearer auth redacted, got %q", headers["Authorization"])
	}
	if headers["X-API-Key"] != "[X_API_KEY]" {
		t.Fatalf("expected mixed secret header redacted, got %q", headers["X-API-Key"])
	}

	basicHeaders, _ := RedactHeaders("svc", "Basic ${USER}:"+mixedSecrets[3], nil, ClientClaudeCode)
	if basicHeaders["Authorization"] != "[AUTHORIZATION]" {
		t.Fatalf("expected mixed Basic auth redacted, got %q", basicHeaders["Authorization"])
	}

	args, _ := RedactArgs([]string{
		"--header", "Authorization: Bearer " + mixedSecrets[4],
		"-H", "X-API-Key: " + mixedSecrets[5],
		"-H", "Accept: application/json",
		"--header=Authorization: Bearer ${SVC_TOKEN}",
		"-h",
	}, ClientClaudeCode, "svc")
	if args[1] != "Authorization: Bearer [SVC_API_KEY]" {
		t.Fatalf("expected --header Bearer redacted, got %q", args[1])
	}
	if args[3] != "X-API-Key: [X_API_KEY]" {
		t.Fatalf("expected -H secret header redacted, got %q", args[3])
	}
	if args[5] != "Accept: application/json" {
		t.Fatalf("expected non-secret header preserved, got %q", args[5])
	}
	if args[6] != "--header=Authorization: Bearer ${SVC_TOKEN}" {
		t.Fatalf("expected pure env-ref --header preserved, got %q", args[6])
	}
	if args[7] != "-h" {
		t.Fatalf("expected lowercase -h help flag untouched, got %q", args[7])
	}

	redURL, _ := RedactURL("https://mcp.example.com/sse?x-api-key="+mixedSecrets[6]+"&auth_token="+mixedSecrets[7]+"&mode=ro#access_token="+mixedSecrets[8]+"&tab=main", ClientGeneric, "svc")
	if redURL != "https://mcp.example.com/sse?x-api-key=[X_API_KEY]&auth_token=[AUTH_TOKEN]&mode=ro#access_token=[ACCESS_TOKEN]&tab=main" {
		t.Fatalf("unexpected query/fragment redaction: %q", redURL)
	}

	blob, err := json.Marshal(map[string]any{"env": env, "headers": headers, "basic": basicHeaders, "args": args, "url": redURL})
	if err != nil {
		t.Fatal(err)
	}
	out := string(blob)
	for _, s := range mixedSecrets {
		if strings.Contains(out, s) {
			t.Fatalf("mixed secret %q leaked: %s", s, out)
		}
	}
}
