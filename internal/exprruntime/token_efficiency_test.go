package exprruntime_test

import (
	"testing"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/stretchr/testify/require"
)

func TestTokenEfficiencyBindings(t *testing.T) {
	env, err := exprruntime.New(nil)
	require.NoError(t, err)
	tokenizer := (&detect.Detector{}).Tokenizer()
	require.NotNil(t, tokenizer)

	for _, tc := range []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "wordlist-assisted check",
			expr: `filter.failsTokenEfficiency(finding["secret"])`,
			want: true,
		},
		{
			name: "ratio-only check",
			expr: `filter.tokenRatio(finding["secret"]) >= 2.5`,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prg, err := env.CompileFilter(tc.expr, tokenizer)
			require.NoError(t, err)

			got, err := env.EvalFilter(prg, map[string]any{"secret": "linkedinX9qB2mK7pR4zT8"}, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTokenRatio(t *testing.T) {
	env, err := exprruntime.New(nil)
	require.NoError(t, err)
	tokenizer := (&detect.Detector{}).Tokenizer()
	require.NotNil(t, tokenizer)

	prg, err := env.CompileFilter(`filter.tokenRatio(finding["secret"]) >= 2.5`, tokenizer)
	require.NoError(t, err)

	got, err := env.EvalFilter(prg, map[string]any{"secret": "this-is-a-long-readable-placeholder-value"}, nil)
	require.NoError(t, err)
	require.True(t, got)
}
