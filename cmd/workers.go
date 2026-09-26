package cmd

import "runtime"

// Sources choose their own bounded I/O concurrency. --jobs controls detection;
// --provider-workers controls credential evaluation independently.
const (
	// Zero means GOMAXPROCS detection slots, regardless of source type.
	// A positive default or --jobs value is also capped at GOMAXPROCS.
	defaultScanWorkers = 0

	// Up to 10 credential evaluations per scan. Each slot runs validation then
	// optional analysis; those stages share this pool. --provider-workers
	// overrides it independently of --jobs; --offline disables this stage.
	defaultAnalyzeWorkers = 10
)

func resolveScanWorkers(configured int) int {
	processorCount := max(runtime.GOMAXPROCS(0), 1)
	if configured == 0 {
		configured = defaultScanWorkers
	}
	if configured == 0 {
		return processorCount
	}
	return min(configured, processorCount)
}

func resolveAnalyzeWorkers(configured int) int {
	if configured == 0 {
		return defaultAnalyzeWorkers
	}
	return configured
}
