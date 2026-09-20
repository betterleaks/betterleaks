package cmd

import "runtime"

// Independent limits for the three pipeline stages; slots are not shared.
//
// --jobs / -j controls source and detection concurrency:
//   - Omitted or 0: source uses 4 workers (filesystem: 40); detection uses GOMAXPROCS.
//   - N > 0: source gets N slots; detection gets min(N, GOMAXPROCS) separate slots.
//     Sources may impose tighter limits, such as the Git history CPU cap.
//   - Analyze is unaffected: --provider-workers controls its separate pool.
//
// Example: -j 8 with GOMAXPROCS=10 allows up to 8 source operations AND 8
// detections, plus the default 10 credential evaluations when online.
const (
	// Git, S3, GitHub, GitLab, and Hugging Face get 4 source slots by default.
	// Git history also caps processes at GOMAXPROCS. --jobs overrides this default.
	defaultSourceWorkers = 4

	// Zero means GOMAXPROCS detection slots, regardless of source type.
	// A positive default or --jobs value is also capped at GOMAXPROCS.
	defaultScanWorkers = 0

	// Up to 10 credential evaluations per scan. Each slot runs validation then
	// optional analysis; those stages share this pool. --provider-workers
	// overrides it independently of --jobs; --offline disables this stage.
	defaultAnalyzeWorkers = 10
)

// Filesystem exception: 40 readers overlap file I/O while detection keeps its
// own CPU-sized pool. --jobs overrides this just like the general source default.
const defaultFilesystemWorkers = 120

func resolveSourceWorkers(configured, fallback int) int {
	if configured == 0 {
		return fallback
	}
	return configured
}

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
