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
	command := func(sourceWorkers, detectWorkers, gitWorkers int) *cobra.Command {
		cmd := new(cobra.Command)
		cmd.Flags().Int("source-workers", sourceWorkers, "")
		cmd.Flags().Int("detect-workers", detectWorkers, "")
		cmd.Flags().Int("git-workers", gitWorkers, "")
		return cmd
	}

	require.NoError(t, validateConcurrencyFlags(command(0, 0, 0)))
	require.NoError(t, validateConcurrencyFlags(command(4, 2, 3)))
	require.EqualError(t, validateConcurrencyFlags(command(-1, 2, 3)), "--source-workers must be non-negative")
	require.EqualError(t, validateConcurrencyFlags(command(4, -1, 3)), "--detect-workers must be non-negative")
	require.EqualError(t, validateConcurrencyFlags(command(4, 2, -1)), "--git-workers must be non-negative")
}
