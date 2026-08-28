package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanFlagsAreCommandLocal(t *testing.T) {
	scanOnly := []string{
		"exit-code",
		"silent",
		"report",
		"confidence",
		"max-target-megabytes",
		"source-workers",
		"detect-workers",
		"ignore-allow-comments",
		"redact",
		"no-banner",
		"disable-rule",
		"isolate-rule",
		"match-context",
		"max-decode-depth",
		"max-archive-depth",
		"validation",
		"validation-status",
		"validation-workers",
		"validation-debug",
		"diagnostics",
		"diagnostics-dir",
	}

	validate := newValidateCmd()
	for _, name := range scanOnly {
		require.Nil(t, rootCmd.PersistentFlags().Lookup(name), name)
		require.Nil(t, configCmd.LocalNonPersistentFlags().Lookup(name), name)
		require.Nil(t, validate.LocalNonPersistentFlags().Lookup(name), name)
		for _, cmd := range scanCommands() {
			require.NotNil(t, cmd.LocalNonPersistentFlags().Lookup(name), "%s: %s", cmd.Name(), name)
		}
	}

	sharedWithValidate := []string{
		"jsonl",
		"validation-timeout",
		"validation-max-requests",
		"validation-rps",
		"validation-rps-rule",
		"validation-extract-empty",
		"validation-env-vars",
	}
	for _, name := range sharedWithValidate {
		require.Nil(t, rootCmd.PersistentFlags().Lookup(name), name)
		require.Nil(t, configCmd.LocalNonPersistentFlags().Lookup(name), name)
		require.NotNil(t, validate.LocalNonPersistentFlags().Lookup(name), name)
		for _, cmd := range scanCommands() {
			require.NotNil(t, cmd.LocalNonPersistentFlags().Lookup(name), "%s: %s", cmd.Name(), name)
		}
	}
}
