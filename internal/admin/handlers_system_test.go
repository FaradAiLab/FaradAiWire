package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

func TestHostResources_Endpoint(t *testing.T) {
	server := NewAdminServer(nil, nil, nil)
	handler := server.Handler()

	// 1. GET request should return 200 OK with valid HostResources
	req := httptest.NewRequest(http.MethodGet, "/admin/host/resources", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var res HostResources
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if res.TotalBytes == 0 {
		t.Errorf("expected TotalBytes > 0, got %d", res.TotalBytes)
	}
	if res.AvailableBytes == 0 {
		t.Errorf("expected AvailableBytes > 0, got %d", res.AvailableBytes)
	}
	if res.CPUPercent < 0 || res.CPUPercent > 100 {
		t.Errorf("expected CPUPercent between 0 and 100, got %f", res.CPUPercent)
	}

	// 2. POST request should return 405 Method Not Allowed
	postReq := httptest.NewRequest(http.MethodPost, "/admin/host/resources", nil)
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 Method Not Allowed on POST, got %d", postRec.Code)
	}
}

func TestHostResources_CgroupV2(t *testing.T) {
	tmpDir := t.TempDir()

	// 4GB limit, 1GB current usage
	maxBytes := uint64(4 * 1024 * 1024 * 1024)
	curBytes := uint64(1 * 1024 * 1024 * 1024)

	if err := os.WriteFile(filepath.Join(tmpDir, "memory.max"), []byte("4294967296\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.max: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "memory.current"), []byte("1073741824\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.current: %v", err)
	}

	res := collectHostResources(tmpDir, nil)

	if !res.CgroupLimited {
		t.Errorf("expected CgroupLimited to be true for cgroup v2")
	}
	if res.TotalBytes != maxBytes {
		t.Errorf("expected TotalBytes %d, got %d", maxBytes, res.TotalBytes)
	}
	if res.UsedBytes != curBytes {
		t.Errorf("expected UsedBytes %d, got %d", curBytes, res.UsedBytes)
	}
	expectedAvail := maxBytes - curBytes
	if res.AvailableBytes != expectedAvail {
		t.Errorf("expected AvailableBytes %d, got %d", expectedAvail, res.AvailableBytes)
	}
}

func TestHostResources_CgroupV1(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupMemDir := filepath.Join(tmpDir, "memory")
	if err := os.MkdirAll(cgroupMemDir, 0755); err != nil {
		t.Fatalf("failed to create cgroup v1 memory dir: %v", err)
	}

	// 2GB limit, 512MB usage
	limitBytes := uint64(2 * 1024 * 1024 * 1024)
	usageBytes := uint64(512 * 1024 * 1024)

	if err := os.WriteFile(filepath.Join(cgroupMemDir, "memory.limit_in_bytes"), []byte("2147483648\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.limit_in_bytes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupMemDir, "memory.usage_in_bytes"), []byte("536870912\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.usage_in_bytes: %v", err)
	}

	res := collectHostResources(tmpDir, nil)

	if !res.CgroupLimited {
		t.Errorf("expected CgroupLimited to be true for cgroup v1")
	}
	if res.TotalBytes != limitBytes {
		t.Errorf("expected TotalBytes %d, got %d", limitBytes, res.TotalBytes)
	}
	if res.UsedBytes != usageBytes {
		t.Errorf("expected UsedBytes %d, got %d", usageBytes, res.UsedBytes)
	}
	expectedAvail := limitBytes - usageBytes
	if res.AvailableBytes != expectedAvail {
		t.Errorf("expected AvailableBytes %d, got %d", expectedAvail, res.AvailableBytes)
	}
}

func TestHostResources_CgroupV1_UnlimitedFallback(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupMemDir := filepath.Join(tmpDir, "memory")
	if err := os.MkdirAll(cgroupMemDir, 0755); err != nil {
		t.Fatalf("failed to create cgroup v1 memory dir: %v", err)
	}

	// 9223372036854771712 indicates unlimited / host memory
	if err := os.WriteFile(filepath.Join(cgroupMemDir, "memory.limit_in_bytes"), []byte("9223372036854771712\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.limit_in_bytes: %v", err)
	}

	res := collectHostResources(tmpDir, nil)

	if res.CgroupLimited {
		t.Errorf("expected CgroupLimited to be false for unlimited cgroup v1")
	}
	if res.TotalBytes == 0 {
		t.Errorf("expected host TotalBytes > 0")
	}
}

func TestHostResources_OllamaRSS_Fallback(t *testing.T) {
	activeModel := &guard.Model{
		ID:            "mica-v0.5",
		RAMRequiredMB: 2950,
		IsActive:      true,
	}

	rss := resolveOllamaRSS(activeModel)
	if rss == 0 {
		t.Errorf("expected non-zero RSS from either live Ollama or active model fallback")
	}
}
