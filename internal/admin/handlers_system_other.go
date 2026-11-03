//go:build !darwin

package admin

// resolveDarwinMemory is a no-op on non-Darwin platforms.
func resolveDarwinMemory() (total, available uint64, ok bool) {
	return 0, 0, false
}

// resolveDarwinSwap is a no-op on non-Darwin platforms.
func resolveDarwinSwap() (total, used uint64, ok bool) {
	return 0, 0, false
}

// resolveDarwinCPU is a no-op on non-Darwin platforms.
func resolveDarwinCPU(numCPU float64) (float64, bool) {
	return 0, false
}
