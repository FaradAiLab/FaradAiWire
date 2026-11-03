package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

// HostResources represents workstation hardware capacity and real-time utilization.
type HostResources struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	CPUPercent     float64 `json:"cpu_percent"`
	CgroupLimited  bool    `json:"cgroup_limited"`
	OllamaRSSBytes uint64  `json:"ollama_rss_bytes"`
}

// defaultCgroupBasePath defines the canonical Linux cgroup filesystem mount point.
var defaultCgroupBasePath = "/sys/fs/cgroup"

// handleHostResources serves real-time host hardware metrics for the Web Console KV Profiler and Host Telemetry Bar.
// Endpoint: GET /admin/host/resources
func (a *AdminServer) handleHostResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET method is supported for host telemetry",
		})
		return
	}

	var activeModel *guard.Model
	if cat := a.getGuardCatalog(); cat != nil {
		activeModel, _ = cat.GetActive(r.Context())
	}

	res := collectHostResources(defaultCgroupBasePath, activeModel)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// collectHostResources samples cgroup/OS memory, swap, CPU load, and SLM engine RSS.
func collectHostResources(cgroupRoot string, activeModel *guard.Model) HostResources {
	total, avail, used, isCgroup := resolveMemory(cgroupRoot)
	swapTotal, swapUsed := resolveSwap()
	cpuPct := resolveCPU()
	ollamaRSS := resolveOllamaRSS(activeModel)

	return HostResources{
		TotalBytes:     total,
		AvailableBytes: avail,
		UsedBytes:      used,
		SwapTotalBytes: swapTotal,
		SwapUsedBytes:  swapUsed,
		CPUPercent:     math.Round(cpuPct*10) / 10,
		CgroupLimited:  isCgroup,
		OllamaRSSBytes: ollamaRSS,
	}
}

// resolveMemory determines available memory, prioritizing container cgroups before falling back to host OS memory.
func resolveMemory(cgroupRoot string) (total, available, used uint64, isCgroup bool) {
	if cgroupRoot == "" {
		cgroupRoot = defaultCgroupBasePath
	}

	// 1. Check cgroup v2 (/sys/fs/cgroup/memory.max & memory.current)
	v2MaxPath := filepath.Join(cgroupRoot, "memory.max")
	if maxData, err := os.ReadFile(v2MaxPath); err == nil {
		maxStr := strings.TrimSpace(string(maxData))
		if maxStr != "" && maxStr != "max" {
			if limit, err := strconv.ParseUint(maxStr, 10, 64); err == nil && limit > 0 {
				v2CurPath := filepath.Join(cgroupRoot, "memory.current")
				if curData, err := os.ReadFile(v2CurPath); err == nil {
					if cur, err := strconv.ParseUint(strings.TrimSpace(string(curData)), 10, 64); err == nil {
						avail := uint64(0)
						if limit > cur {
							avail = limit - cur
						}
						return limit, avail, cur, true
					}
				}
			}
		}
	}

	// 2. Check cgroup v1 (/sys/fs/cgroup/memory/memory.limit_in_bytes & memory.usage_in_bytes)
	v1LimitPath := filepath.Join(cgroupRoot, "memory", "memory.limit_in_bytes")
	if limitData, err := os.ReadFile(v1LimitPath); err == nil {
		if limit, err := strconv.ParseUint(strings.TrimSpace(string(limitData)), 10, 64); err == nil {
			// Values >= 1<<62 represent unlimited / no cgroup constraint
			if limit > 0 && limit < (1<<62) {
				v1UsagePath := filepath.Join(cgroupRoot, "memory", "memory.usage_in_bytes")
				if usageData, err := os.ReadFile(v1UsagePath); err == nil {
					if cur, err := strconv.ParseUint(strings.TrimSpace(string(usageData)), 10, 64); err == nil {
						avail := uint64(0)
						if limit > cur {
							avail = limit - cur
						}
						return limit, avail, cur, true
					}
				}
			}
		}
	}

	// 3. Fallback to host OS memory
	return readHostMemory()
}

// readHostMemory inspects native host OS metrics (Linux /proc/meminfo or macOS sysctl/vm_stat).
func readHostMemory() (total, available, used uint64, isCgroup bool) {
	// A. Linux /proc/meminfo
	if meminfoData, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvail, memFree uint64
		scanner := bufio.NewScanner(bytes.NewReader(meminfoData))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "MemTotal:":
					memTotal = val * 1024
				case "MemAvailable:":
					memAvail = val * 1024
				case "MemFree:":
					memFree = val * 1024
				}
			}
		}
		if memTotal > 0 {
			if memAvail == 0 {
				memAvail = memFree
			}
			used := uint64(0)
			if memTotal > memAvail {
				used = memTotal - memAvail
			}
			return memTotal, memAvail, used, false
		}
	}

	// B. macOS (Darwin) hw.memsize & vm_stat
	if totalMem, availMem, ok := resolveDarwinMemory(); ok {
		used := uint64(0)
		if totalMem > availMem {
			used = totalMem - availMem
		}
		return totalMem, availMem, used, false
	}

	// C. Fallback: runtime.MemStats minimal baseline
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	total = 16 * 1024 * 1024 * 1024 // Assume standard 16GB baseline if unresolvable
	used = m.Sys
	available = total - used
	return total, available, used, false
}

// resolveSwap calculates total and used swap memory across Linux and macOS.
func resolveSwap() (total, used uint64) {
	// A. Linux /proc/meminfo
	if meminfoData, err := os.ReadFile("/proc/meminfo"); err == nil {
		var swapTotal, swapFree uint64
		scanner := bufio.NewScanner(bytes.NewReader(meminfoData))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "SwapTotal:":
					swapTotal = val * 1024
				case "SwapFree:":
					swapFree = val * 1024
				}
			}
		}
		if swapTotal > 0 {
			used := uint64(0)
			if swapTotal > swapFree {
				used = swapTotal - swapFree
			}
			return swapTotal, used
		}
	}

	// B. macOS sysctl vm.swapusage
	if totalSwap, usedSwap, ok := resolveDarwinSwap(); ok {
		return totalSwap, usedSwap
	}

	return 0, 0
}

// resolveCPU estimates current CPU load percentage normalized across CPU cores.
func resolveCPU() float64 {
	numCPU := float64(runtime.NumCPU())
	if numCPU <= 0 {
		numCPU = 1.0
	}

	// 1. Linux /proc/loadavg
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if l1, err := strconv.ParseFloat(fields[0], 64); err == nil && l1 >= 0 {
				pct := (l1 / numCPU) * 100.0
				if pct > 100.0 {
					pct = 100.0
				}
				return pct
			}
		}
	}

	// 2. Darwin sysctl vm.loadavg
	if cpuPct, ok := resolveDarwinCPU(numCPU); ok {
		return cpuPct
	}

	return 5.0 // Healthy fallback baseline
}

// resolveOllamaRSS queries Ollama /api/ps to inspect active runner RSS memory,
// falling back to active model catalog RAM requirement if unreachable.
func resolveOllamaRSS(activeModel *guard.Model) uint64 {
	client := &http.Client{Timeout: 300 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:11434/api/ps", nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var psResp struct {
					Models []struct {
						Size     uint64 `json:"size"`
						SizeVRAM uint64 `json:"size_vram"`
					} `json:"models"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&psResp); err == nil && len(psResp.Models) > 0 {
					totalRSS := uint64(0)
					for _, m := range psResp.Models {
						if m.Size > 0 {
							totalRSS += m.Size
						} else if m.SizeVRAM > 0 {
							totalRSS += m.SizeVRAM
						}
					}
					if totalRSS > 0 {
						return totalRSS
					}
				}
			}
		}
	}

	// Fallback to active catalog model RAM requirement if running
	if activeModel != nil && activeModel.IsActive && activeModel.RAMRequiredMB > 0 {
		return uint64(activeModel.RAMRequiredMB) * 1024 * 1024
	}

	return 0
}
