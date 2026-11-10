package admin

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProbeAndDiscoverMCPToolsStdio_StripsHostSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	t.Setenv("ADMIN_API_KEY", "canary-admin-secret-123")
	t.Setenv("API_KEY", "canary-api-secret-456")
	t.Setenv("ALLOWED_EXPLICIT_VAR", "explicit-ok-789")

	script := `
while IFS= read -r line; do
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}\n'
      ;;
    *'"tools/list"'*)
      dumped=$(env | tr '\n' '|')
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"env_probe","description":"%s"}]}}\n' "$dumped"
      exit 0
      ;;
  esac
done
`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Case 1: empty env must still sanitize host secrets (must not inherit os.Environ)
	tools, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", script}, nil)
	if err != nil {
		t.Fatalf("probe with empty env failed: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	desc, _ := tools[0]["description"].(string)
	if strings.Contains(desc, "canary-admin-secret-123") || strings.Contains(desc, "canary-api-secret-456") {
		t.Fatalf("host secrets leaked into stdio probe with empty env: %s", desc)
	}

	// Case 2: explicit ${VAR} ref is expanded while unrelated host secrets stay absent
	tools2, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", script}, []string{"PASSED_REF=${ALLOWED_EXPLICIT_VAR}"})
	if err != nil {
		t.Fatalf("probe with explicit env failed: %v", err)
	}
	desc2, _ := tools2[0]["description"].(string)
	if strings.Contains(desc2, "canary-admin-secret-123") || strings.Contains(desc2, "canary-api-secret-456") {
		t.Fatalf("host secrets leaked into stdio probe with explicit env: %s", desc2)
	}
	if !strings.Contains(desc2, "PASSED_REF=explicit-ok-789") {
		t.Fatalf("expected expanded PASSED_REF=explicit-ok-789 in probe env, got: %s", desc2)
	}
}

func TestProbeAndDiscoverMCPToolsStdio_KillsGrandchildOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process group test skipped on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	// Spawn a grandchild sleep holding stdout open while parent drains stdin without replying
	_, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", "sleep 30 & while IFS= read -r _; do :; done"}, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected grandchild process group to be killed promptly, took %v", elapsed)
	}
}
