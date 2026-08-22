package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestConcurrencyFlags(t *testing.T) {
	detectWorkers := rootCmd.PersistentFlags().Lookup("detect-workers")
	require.NotNil(t, detectWorkers)
	require.Equal(t, "0", detectWorkers.DefValue)

	sourceWorkers := directoryCmd.Flags().Lookup("source-workers")
	require.NotNil(t, sourceWorkers)
	require.Equal(t, "0", sourceWorkers.DefValue)
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
