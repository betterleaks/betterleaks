package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeProviderFlagAliases(t *testing.T) {
	args, err := normalizeProviderFlagAliases([]string{
		"dir",
		"--validation-workers", "4",
		"--validation-timeout=2s",
		"--validation-rps-rule", "github-pat=1",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"dir",
		"--provider-workers", "4",
		"--provider-timeout=2s",
		"--provider-rps-rule", "github-pat=1",
	}, args)
}

func TestNormalizeProviderFlagAliasesRejectsMixedSpellings(t *testing.T) {
	_, err := normalizeProviderFlagAliases([]string{
		"dir", "--provider-timeout", "1s", "--validation-timeout", "2s",
	})
	require.ErrorContains(t, err, "cannot be combined")
}

func TestNormalizeProviderFlagAliasesLeavesArgumentsAfterTerminator(t *testing.T) {
	args, err := normalizeProviderFlagAliases([]string{"validate", "--", "--validation-timeout"})
	require.NoError(t, err)
	assert.Equal(t, []string{"validate", "--", "--validation-timeout"}, args)
}
