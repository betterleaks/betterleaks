package cmd

import "runtime"

type workerProfile uint8

const (
	directoryWorkerProfile workerProfile = iota
	objectWorkerProfile
	streamWorkerProfile
	gitWorkerProfile
	providerWorkerProfile
)

const (
	maxAutomaticProviderWorkers  = 4
	maxAutomaticGitWorkers       = 4
	automaticFileWorkersPerCPU   = 12
	maxAutomaticFileWorkers      = 120
	automaticObjectWorkersPerCPU = 2
)

type workerPlan struct {
	Source  int
	Scanner int
}

func resolveWorkerPlan(configured int, profile workerProfile) workerPlan {
	processorCount := max(runtime.GOMAXPROCS(0), 1)
	if configured > 0 {
		sourceWorkers := configured
		if profile == gitWorkerProfile {
			sourceWorkers = min(sourceWorkers, processorCount)
		}
		return workerPlan{
			Source:  sourceWorkers,
			Scanner: min(configured, processorCount),
		}
	}

	switch profile {
	case directoryWorkerProfile:
		return workerPlan{
			Source:  max(processorCount, min(processorCount*automaticFileWorkersPerCPU, maxAutomaticFileWorkers)),
			Scanner: processorCount,
		}
	case objectWorkerProfile:
		return workerPlan{
			Source:  processorCount * automaticObjectWorkersPerCPU,
			Scanner: processorCount,
		}
	case streamWorkerProfile:
		return workerPlan{Source: processorCount, Scanner: processorCount}
	case gitWorkerProfile:
		return workerPlan{Source: min(processorCount, maxAutomaticGitWorkers), Scanner: processorCount}
	case providerWorkerProfile:
		workers := min(processorCount, maxAutomaticProviderWorkers)
		return workerPlan{Source: workers, Scanner: workers}
	default:
		panic("unknown worker profile")
	}
}
