package rules

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/stretchr/testify/require"
)

func TestPublicAPIKeyProviderUsesLineClampedMatchContext(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileFilter(`let providerMatchContext = finding["raw"][max(finding["raw_match_start"] - 150, finding["raw_line_start"]):min(finding["raw_match_end"] + 50, finding["raw_line_end"])]; false`+buildTestAndPublicAPIFilters(), nil)
	require.NoError(t, err)

	secret := "pk_live_" + strings.Repeat("a", 24)
	line := "stripe" + strings.Repeat("x", 140) + secret
	skip, err := runtime.EvalFilter(program, map[string]any{
		"secret":          secret,
		"raw":             "stripe\n" + line,
		"raw_match_start": len("stripe\n") + len(line) - len(secret),
		"raw_match_end":   len("stripe\n") + len(line),
		"raw_line_start":  len("stripe\n"),
		"raw_line_end":    len("stripe\n") + len(line),
	}, nil)
	require.NoError(t, err)
	require.True(t, skip)

	line = strings.Repeat("x", 140) + secret
	skip, err = runtime.EvalFilter(program, map[string]any{
		"secret":          secret,
		"raw":             "stripe\n" + line,
		"raw_match_start": len("stripe\n") + len(line) - len(secret),
		"raw_match_end":   len("stripe\n") + len(line),
		"raw_line_start":  len("stripe\n"),
		"raw_line_end":    len("stripe\n") + len(line),
	}, nil)
	require.NoError(t, err)
	require.False(t, skip)
}

func TestGenericAPIKeyUsesOriginalFiftyByteWindow(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileFilter(`let genericMatchContext = finding["raw"][max(finding["raw_match_start"] - 50, finding["raw_line_start"]):min(finding["raw_match_end"], finding["raw_line_end"])]; filter.matchesAny(genericMatchContext, [`+"`"+genericAPIKeyMatchFilter+"`"+`])`, nil)
	require.NoError(t, err)

	secret := strings.Repeat("A", 20)
	raw := "primary_key" + strings.Repeat("x", 60) + secret
	skip, err := runtime.EvalFilter(program, map[string]any{
		"raw":             raw,
		"raw_match_start": len(raw) - len(secret),
		"raw_match_end":   len(raw),
		"raw_line_start":  0,
		"raw_line_end":    len(raw),
	}, nil)
	require.NoError(t, err)
	require.False(t, skip)
}
