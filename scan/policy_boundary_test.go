package scan

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestConfigPathDoesNotControlSDKScanning(t *testing.T) {
	cfg := &config.Config{Path: "rules.toml", Rules: []config.Rule{{ID: "token", Regex: `TOKEN`}}}
	for _, exclude := range []bool{false, true} {
		var options []Option
		if exclude {
			options = append(options, WithExcludedPaths("rules.toml"))
		}
		scanner, err := New(cfg, options...)
		require.NoError(t, err)
		count := 0
		_, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN"), Attributes: map[string]string{sources.AttrPath: "rules.toml"}}, func(f report.Finding) error { count++; return nil })
		require.NoError(t, err)
		if exclude {
			require.Zero(t, count)
		} else {
			require.Equal(t, 1, count)
		}
	}
}

func TestPathOnlyFindingsHonorFilters(t *testing.T) {
	for _, global := range []bool{false, true} {
		cfg := &config.Config{Rules: []config.Rule{{ID: "path", Path: `\.env$`}}}
		expression := `attributes.path == "skip.env" && finding.fragment_raw == "" && finding.match_start_idx == 0`
		if global {
			cfg.Filter = expression
		} else {
			cfg.Rules[0].Filter = expression
		}
		scanner, err := New(cfg, WithPrecompile())
		require.NoError(t, err)
		for _, path := range []string{"skip.env", "keep.env"} {
			count := 0
			_, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("content"), Attributes: map[string]string{sources.AttrPath: path}}, func(f report.Finding) error { count++; return nil })
			require.NoError(t, err)
			if path == "skip.env" {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
		}
	}
}
