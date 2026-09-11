package cmd

import (
	"fmt"
	"math"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
)

func mustGetBoolFlag(cmd *cobra.Command, name string) bool {
	value, err := cmd.Flags().GetBool(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetIntFlag(cmd *cobra.Command, name string) int {
	value, err := cmd.Flags().GetInt(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetUIntFlag(cmd *cobra.Command, name string) uint {
	value, err := cmd.Flags().GetUint(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetStringFlag(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetSizeFlag(cmd *cobra.Command, name string) int64 {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	n, err := parseSize(value)
	if err != nil {
		logging.Fatal().Err(err).Msgf("invalid size for flag --%s: %q", name, value)
	}
	return n
}

// parseSize converts a human-readable size string to bytes. Empty string returns 0.
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := humanize.ParseBytes(s)
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("size %q overflows int64 (max %d bytes)", s, int64(math.MaxInt64))
	}
	return int64(n), nil
}

func mustGetFloat64Flag(cmd *cobra.Command, name string) float64 {
	value, err := cmd.Flags().GetFloat64(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}
