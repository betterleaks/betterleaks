package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
)

func TestPublicAPIKeyProviderUsesLineClampedContext(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileFilter(`let providerMatchContext = finding["local_line"][max(finding["local_line_match_start_idx"] - 150, 0):min(finding["local_line_match_end_idx"] + 50, len(finding["local_line"]))]; false`+buildTestAndPublicAPIFilters(), nil)
	require.NoError(t, err)

	secret := "pk_live_" + strings.Repeat("a", 24)
	line := "stripe" + strings.Repeat("x", 140) + secret
	skip, err := runtime.EvalFilter(program, map[string]any{
		"secret":                     secret,
		"local_line":                 line,
		"local_line_match_start_idx": len(line) - len(secret),
		"local_line_match_end_idx":   len(line),
	}, nil)
	require.NoError(t, err)
	require.True(t, skip)

	line = strings.Repeat("x", 140) + secret
	skip, err = runtime.EvalFilter(program, map[string]any{
		"secret":                     secret,
		"local_line":                 line,
		"local_line_match_start_idx": len(line) - len(secret),
		"local_line_match_end_idx":   len(line),
	}, nil)
	require.NoError(t, err)
	require.False(t, skip)
}

func TestGenericAPIKeyUsesRestrictedPrefix(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileFilter(`let genericMatchPrefix = filter.findMatch(finding["local_line"][max(finding["local_line_match_start_idx"] - 50, 0):finding["local_line_match_start_idx"]], `+"`[\\w.-]{0,50}$`"+`); let genericMatchContext = genericMatchPrefix + finding["local_line"][finding["local_line_match_start_idx"]:finding["local_line_match_end_idx"]]; filter.matchesAny(genericMatchContext, [`+"`"+genericAPIKeyMatchFilter+"`"+`])`, nil)
	require.NoError(t, err)

	secret := strings.Repeat("A", 20)
	for _, tc := range []struct {
		name   string
		prefix string
		want   bool
	}{
		{"contiguous", "primary_key" + strings.Repeat("x", 10), true},
		{"stops at disallowed character", "primary_key!" + strings.Repeat("x", 10), false},
		{"limited to fifty bytes", "primary_key" + strings.Repeat("x", 50), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.prefix + secret
			skip, err := runtime.EvalFilter(program, map[string]any{
				"local_line":                 line,
				"local_line_match_start_idx": len(tc.prefix),
				"local_line_match_end_idx":   len(line),
			}, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, skip)
		})
	}
}
