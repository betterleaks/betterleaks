package cmd

import "runtime"

type jobProfile uint8

const (
	directoryJobProfile jobProfile = iota
	objectJobProfile
	streamJobProfile
	gitJobProfile
	providerJobProfile
)

const (
	maxAutomaticProviderJobs  = 4
	maxAutomaticGitJobs       = 4
	automaticFileJobsPerCPU   = 4
	maxAutomaticFileJobs      = 40
	automaticObjectJobsPerCPU = 2
)

type jobPlan struct {
	Source  int
	Scanner int
}

func resolveJobPlan(configured int, profile jobProfile) jobPlan {
	processorJobs := max(runtime.GOMAXPROCS(0), 1)
	if configured > 0 {
		sourceJobs := configured
		if profile == gitJobProfile {
			sourceJobs = min(sourceJobs, processorJobs)
		}
		return jobPlan{
			Source:  sourceJobs,
			Scanner: min(configured, processorJobs),
		}
	}

	switch profile {
	case directoryJobProfile:
		return jobPlan{
			Source:  max(processorJobs, min(processorJobs*automaticFileJobsPerCPU, maxAutomaticFileJobs)),
			Scanner: processorJobs,
		}
	case objectJobProfile:
		return jobPlan{
			Source:  processorJobs * automaticObjectJobsPerCPU,
			Scanner: processorJobs,
		}
	case streamJobProfile:
		return jobPlan{Source: processorJobs, Scanner: processorJobs}
	case gitJobProfile:
		return jobPlan{Source: min(processorJobs, maxAutomaticGitJobs), Scanner: processorJobs}
	case providerJobProfile:
		jobs := min(processorJobs, maxAutomaticProviderJobs)
		return jobPlan{Source: jobs, Scanner: jobs}
	default:
		panic("unknown job profile")
	}
}
