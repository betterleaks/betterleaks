package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceWorkersFlag(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "--source-workers=3", "--detect-workers=4")
	require.NoError(t, err)
	require.Equal(t, 3, cli.Directory.SourceWorkers)
	require.Equal(t, 4, cli.Directory.DetectWorkers)

	cli, err = parseCLIForTest(t, "git", "--git-workers=5")
	require.NoError(t, err)
	require.Equal(t, 5, cli.Git.GitWorkers)

	cli, err = parseCLIForTest(t, "s3", "--workers=6", "s3://bucket")
	require.NoError(t, err)
	require.Equal(t, 6, cli.S3.Workers)
}

func TestResolveGitWorkers(t *testing.T) {
	tests := []struct {
		name          string
		sourceWorkers int
		gitWorkers    int
		want          int
		wantErr       bool
	}{
		{name: "defaults", want: 0},
		{name: "source workers", sourceWorkers: 16, want: 16},
		{name: "git workers alias", gitWorkers: 16, want: 16},
		{name: "matching aliases", sourceWorkers: 16, gitWorkers: 16, want: 16},
		{name: "conflicting aliases", sourceWorkers: 8, gitWorkers: 16, wantErr: true},
		{name: "negative source workers", sourceWorkers: -1, wantErr: true},
		{name: "negative git workers", gitWorkers: -1, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveGitWorkers(test.sourceWorkers, test.gitWorkers)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}
