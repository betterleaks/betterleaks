package cmd

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLegacyProviderFlagsRejected(t *testing.T) {
	for _, flag := range []string{
		"--validation-workers=4", "--validation-debug", "--validation-timeout=2s",
		"--validation-max-requests=5", "--validation-rps=1", "--validation-rps-rule=github-pat=1",
		"--validation-env-vars=GITHUB_BASE_URL",
	} {
		t.Run(flag, func(t *testing.T) {
			_, err := parseCLIForTest(t, "dir", flag)
			require.ErrorContains(t, err, "unknown flag")
		})
	}
}
