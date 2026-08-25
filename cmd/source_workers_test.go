package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceWorkersFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("source-workers")
	require.NotNil(t, flag)
	require.Equal(t, "0", flag.DefValue)
	require.NotNil(t, s3Cmd.Flags().Lookup("workers"))
}
