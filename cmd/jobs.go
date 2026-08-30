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
	maxAutomaticGitJobs       = 4
	maxAutomaticProviderJobs  = 4
	automaticFileJobsPerCPU   = 4
	maxAutomaticFileJobs      = 40
	automaticObjectJobsPerCPU = 2
)

type jobPlan struct {
	Source   int
	Detector int
}

func resolveJobPlan(configured int, profile jobProfile) jobPlan {
	processorJobs := max(runtime.GOMAXPROCS(0), 1)
	if configured > 0 {
		return jobPlan{
			Source:   configured,
			Detector: min(configured, processorJobs),
		}
	}

	switch profile {
	case directoryJobProfile:
		return jobPlan{
			Source:   max(processorJobs, min(processorJobs*automaticFileJobsPerCPU, maxAutomaticFileJobs)),
			Detector: processorJobs,
		}
	case objectJobProfile:
		return jobPlan{
			Source:   processorJobs * automaticObjectJobsPerCPU,
			Detector: processorJobs,
		}
	case streamJobProfile:
		return jobPlan{Source: processorJobs, Detector: processorJobs}
	case gitJobProfile:
		jobs := min(processorJobs, maxAutomaticGitJobs)
		return jobPlan{Source: jobs, Detector: jobs}
	case providerJobProfile:
		jobs := min(processorJobs, maxAutomaticProviderJobs)
		return jobPlan{Source: jobs, Detector: jobs}
	default:
		panic("unknown job profile")
	}
}
