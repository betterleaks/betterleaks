package cmd

// Sources choose their own bounded I/O concurrency. --jobs controls detection;
// --provider-workers controls credential evaluation independently.
const (
	// Up to 10 credential evaluations per scan. Each slot runs validation then
	// optional analysis; those stages share this pool. --provider-workers
	// overrides it independently of --jobs; --offline disables this stage.
	defaultAnalyzeWorkers = 10
)

func resolveAnalyzeWorkers(configured int) int {
	if configured == 0 {
		return defaultAnalyzeWorkers
	}
	return configured
}
