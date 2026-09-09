package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreReceiveFlagsRegistered(t *testing.T) {
	require.NotNil(t, gitCmd.Flags().Lookup("pre-receive"))
	require.NotNil(t, gitCmd.Flags().Lookup("pre-receive-error-message"))

	preReceive := gitCmd.Flags().Lookup("pre-receive")
	require.Equal(t, "false", preReceive.DefValue)

	errMsg := gitCmd.Flags().Lookup("pre-receive-error-message")
	require.Equal(t, "", errMsg.DefValue)
}
