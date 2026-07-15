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
	program, err := runtime.CompileFilter(`let providerMatchContext = finding["fragment_raw"][max(finding["match_start_idx"] - 150, finding["match_line_start_idx"]):min(finding["match_end_idx"] + 50, finding["match_line_end_idx"])]; false`+buildTestAndPublicAPIFilters(), nil)
	require.NoError(t, err)

	secret := "pk_live_" + strings.Repeat("a", 24)
	line := "stripe" + strings.Repeat("x", 140) + secret
	skip, err := runtime.EvalFilter(program, map[string]any{
		"secret":               secret,
		"fragment_raw":         "stripe\n" + line,
		"match_start_idx":      len("stripe\n") + len(line) - len(secret),
		"match_end_idx":        len("stripe\n") + len(line),
		"match_line_start_idx": len("stripe\n"),
		"match_line_end_idx":   len("stripe\n") + len(line),
	}, nil)
	require.NoError(t, err)
	require.True(t, skip)

	line = strings.Repeat("x", 140) + secret
	skip, err = runtime.EvalFilter(program, map[string]any{
		"secret":               secret,
		"fragment_raw":         "stripe\n" + line,
		"match_start_idx":      len("stripe\n") + len(line) - len(secret),
		"match_end_idx":        len("stripe\n") + len(line),
		"match_line_start_idx": len("stripe\n"),
		"match_line_end_idx":   len("stripe\n") + len(line),
	}, nil)
	require.NoError(t, err)
	require.False(t, skip)
}

func TestGenericAPIKeyUsesRestrictedPrefix(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileFilter(`let genericMatchPrefix = filter.findMatch(finding["fragment_raw"][max(finding["match_start_idx"] - 50, finding["match_line_start_idx"]):finding["match_start_idx"]], `+"`[\\w.-]{0,50}$`"+`); let genericMatchContext = genericMatchPrefix + finding["fragment_raw"][finding["match_start_idx"]:finding["match_end_idx"]]; filter.matchesAny(genericMatchContext, [`+"`"+genericAPIKeyMatchFilter+"`"+`])`, nil)
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
			raw := tc.prefix + secret
			skip, err := runtime.EvalFilter(program, map[string]any{
				"fragment_raw":         raw,
				"match_start_idx":      len(tc.prefix),
				"match_end_idx":        len(raw),
				"match_line_start_idx": 0,
				"match_line_end_idx":   len(raw),
			}, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, skip)
		})
	}
}
