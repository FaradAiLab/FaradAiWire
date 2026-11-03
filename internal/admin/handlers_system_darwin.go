//go:build darwin

package admin

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// resolveDarwinMemory retrieves physical RAM size via sysctl and available RAM via vm_stat.
func resolveDarwinMemory() (total, available uint64, ok bool) {
	memSize, err := unix.SysctlUint64("hw.memsize")
	if err != nil || memSize == 0 {
		return 0, 0, false
	}
	avail := readDarwinAvailableMemory()
	if avail > memSize {
		avail = memSize
	}
	return memSize, avail, true
}

// readDarwinAvailableMemory parses macOS vm_stat output to compute available RAM.
func readDarwinAvailableMemory() uint64 {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "vm_stat").Output()
	if err != nil {
		return 8 * 1024 * 1024 * 1024
	}

	pageSize := uint64(4096)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var freePages, inactivePages, speculativePages, purgeablePages uint64

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "page size of") {
			parts := strings.Split(line, "page size of ")
			if len(parts) == 2 {
				sub := strings.Split(parts[1], " ")
				if ps, err := strconv.ParseUint(sub[0], 10, 64); err == nil && ps > 0 {
					pageSize = ps
				}
			}
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			valStr := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".")
			val, _ := strconv.ParseUint(valStr, 10, 64)

			switch key {
			case "Pages free":
				freePages = val
			case "Pages inactive":
				inactivePages = val
			case "Pages speculative":
				speculativePages = val
			case "Pages purgeable":
				purgeablePages = val
			}
		}
	}

	availPages := freePages + inactivePages + speculativePages + purgeablePages
	return availPages * pageSize
}

// resolveDarwinSwap retrieves swap metrics via macOS sysctl vm.swapusage.
func resolveDarwinSwap() (total, used uint64, ok bool) {
	swapStr, err := unix.Sysctl("vm.swapusage")
	if err != nil {
		return 0, 0, false
	}
	// Format: "total = 6144.00M  used = 4544.81M  free = 1599.19M  (encrypted)"
	total = parseSysctlSwapMB(swapStr, "total = ")
	used = parseSysctlSwapMB(swapStr, "used = ")
	return total, used, true
}

func parseSysctlSwapMB(s, prefix string) uint64 {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return 0
	}
	sub := s[idx+len(prefix):]
	endIdx := strings.Index(sub, "M")
	if endIdx == -1 {
		return 0
	}
	numStr := strings.TrimSpace(sub[:endIdx])
	f, err := strconv.ParseFloat(numStr, 64)
	if err != nil || f < 0 {
		return 0
	}
	return uint64(f * 1024 * 1024)
}

// resolveDarwinCPU retrieves current load average via macOS sysctl vm.loadavg.
func resolveDarwinCPU(numCPU float64) (float64, bool) {
	out, err := unix.Sysctl("vm.loadavg")
	if err != nil {
		return 0, false
	}
	// Format: "{ 3.92 3.99 3.89 }"
	clean := strings.Trim(out, "{ }\n\r\t")
	fields := strings.Fields(clean)
	if len(fields) > 0 {
		if l1, err := strconv.ParseFloat(fields[0], 64); err == nil && l1 >= 0 {
			pct := (l1 / numCPU) * 100.0
			if pct > 100.0 {
				pct = 100.0
			}
			return pct, true
		}
	}
	return 0, false
}
