package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceWorkersFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("source-workers")
	require.NotNil(t, flag)
	require.Equal(t, "0", flag.DefValue)
	detectFlag := rootCmd.PersistentFlags().Lookup("detect-workers")
	require.NotNil(t, detectFlag)
	require.Equal(t, "0", detectFlag.DefValue)
	require.NotNil(t, s3Cmd.Flags().Lookup("workers"))
	require.NotNil(t, gitCmd.Flags().Lookup("git-workers"))
	require.Nil(t, githubCmd.Flags().Lookup("git-workers"))
	require.Nil(t, gitlabCmd.Flags().Lookup("git-workers"))
	require.Nil(t, huggingFaceCmd.Flags().Lookup("git-workers"))
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
