package detect

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestDetectorOwnsRegexesFromPatternStrings(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID:          "token",
		Regex:       `token=(?P<secret>[a-z]+)`,
		Path:        `\.env$`,
		SecretGroup: 1,
	}}}
	lazy := mustNewDetector(t, cfg)
	eager := mustNewDetector(t, cfg, WithPrecompile())
	require.NotSame(t, lazy.rulesBySpecificity[0].regex, eager.rulesBySpecificity[0].regex)
	require.NotSame(t, lazy.rulesBySpecificity[0].path, eager.rulesBySpecificity[0].path)

	cfg.Rules[0].Regex = `changed`
	cfg.Rules[0].Path = `\.txt$`
	for _, detector := range []*Detector{lazy, eager} {
		fragment := sources.Fragment{Raw: "token=secret", Attributes: map[string]string{sources.AttrPath: "app.env"}}
		findings := detector.detectFragment(t.Context(), fragment)
		require.Len(t, findings, 1)
		require.Equal(t, "secret", findings[0].Secret)
		require.Equal(t, "secret", findings[0].CaptureGroups["secret"])
		fragment.Attributes[sources.AttrPath] = "app.txt"
		require.Empty(t, detector.detectFragment(t.Context(), fragment))
	}
}
