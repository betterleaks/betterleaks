package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestConcurrencyFlags(t *testing.T) {
	for _, name := range []string{"source-workers", "detect-workers"} {
		flag := rootCmd.PersistentFlags().Lookup(name)
		require.NotNil(t, flag)
		require.Equal(t, "0", flag.DefValue)
	}
}

func TestValidateConcurrencyFlags(t *testing.T) {
	newCommand := func(sourceWorkers, detectWorkers, gitWorkers int) *cobra.Command {
		cmd := new(cobra.Command)
		cmd.Use = "test"
		cmd.Flags().Int("source-workers", sourceWorkers, "")
		cmd.Flags().Int("detect-workers", detectWorkers, "")
		cmd.Flags().Int("git-workers", gitWorkers, "")
		return cmd
	}

	require.NoError(t, validateConcurrencyFlags(newCommand(0, 0, 0)))
	require.NoError(t, validateConcurrencyFlags(newCommand(4, 2, 3)))
	require.EqualError(t, validateConcurrencyFlags(newCommand(-1, 2, 3)), "--source-workers must be non-negative")
	require.EqualError(t, validateConcurrencyFlags(newCommand(4, -1, 3)), "--detect-workers must be non-negative")
	require.EqualError(t, validateConcurrencyFlags(newCommand(4, 2, -1)), "--git-workers must be non-negative")
}

func TestResolveS3WorkersPrecedence(t *testing.T) {
	cmd := new(cobra.Command)
	cmd.Use = "s3"
	cmd.Flags().Int("workers", 0, "")

	require.Equal(t, 6, resolveS3Workers(cmd, 6))
	require.NoError(t, cmd.Flags().Set("workers", "0"))
	require.Equal(t, 0, resolveS3Workers(cmd, 6))
	require.NoError(t, cmd.Flags().Set("workers", "3"))
	require.Equal(t, 3, resolveS3Workers(cmd, 6))
}
