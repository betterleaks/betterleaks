package cmd

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJobsFlag(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "-j", "3")
	require.NoError(t, err)
	require.Equal(t, 3, cli.Directory.Jobs)

	cli, err = parseCLIForTest(t, "git", "--jobs=5")
	require.NoError(t, err)
	require.Equal(t, 5, cli.Git.Jobs)

	cli, err = parseCLIForTest(t, "s3", "-j", "6", "s3://bucket")
	require.NoError(t, err)
	require.Equal(t, 6, cli.S3.Jobs)
}

func TestResolveJobPlan(t *testing.T) {
	cpus := max(runtime.GOMAXPROCS(0), 1)

	explicitJobs := cpus + 3
	wantExplicit := jobPlan{Source: explicitJobs, Detector: cpus}
	require.Equal(t, wantExplicit, resolveJobPlan(explicitJobs, directoryJobProfile))
	require.Equal(t, wantExplicit, resolveJobPlan(explicitJobs, objectJobProfile))
	require.Equal(t, wantExplicit, resolveJobPlan(explicitJobs, streamJobProfile))
	require.Equal(t, jobPlan{Source: cpus, Detector: cpus}, resolveJobPlan(explicitJobs, gitJobProfile))
	require.Equal(t, wantExplicit, resolveJobPlan(explicitJobs, providerJobProfile))

	require.Equal(t,
		jobPlan{Source: max(cpus, min(cpus*automaticFileJobsPerCPU, maxAutomaticFileJobs)), Detector: cpus},
		resolveJobPlan(0, directoryJobProfile),
	)
	require.Equal(t,
		jobPlan{Source: cpus * automaticObjectJobsPerCPU, Detector: cpus},
		resolveJobPlan(0, objectJobProfile),
	)
	require.Equal(t, jobPlan{Source: cpus, Detector: cpus}, resolveJobPlan(0, streamJobProfile))
	require.Equal(t, jobPlan{Source: cpus, Detector: cpus}, resolveJobPlan(0, gitJobProfile))
	providerJobs := min(cpus, maxAutomaticProviderJobs)
	require.Equal(t, jobPlan{Source: providerJobs, Detector: providerJobs}, resolveJobPlan(0, providerJobProfile))
}

func TestResolveJobPlanOneJobIsSerial(t *testing.T) {
	want := jobPlan{Source: 1, Detector: 1}
	require.Equal(t, want, resolveJobPlan(1, directoryJobProfile))
	require.Equal(t, want, resolveJobPlan(1, objectJobProfile))
	require.Equal(t, want, resolveJobPlan(1, streamJobProfile))
	require.Equal(t, want, resolveJobPlan(1, gitJobProfile))
	require.Equal(t, want, resolveJobPlan(1, providerJobProfile))
}

func TestJobsRejectsNegativeValues(t *testing.T) {
	_, err := parseCLIForTest(t, "git", "--jobs=-1")
	require.ErrorContains(t, err, "--jobs must be non-negative")
}

func TestRemovedWorkerFlagsAreRejected(t *testing.T) {
	tests := [][]string{
		{"dir", "--source-workers=2"},
		{"dir", "--detect-workers=2"},
		{"git", "--git-workers=2"},
		{"s3", "--workers=2", "s3://bucket"},
	}
	for _, args := range tests {
		_, err := parseCLIForTest(t, args...)
		require.Error(t, err, "parseCLIForTest(%q)", args)
	}
}
