//go:build !race

package exprruntime_test

import (
	"testing"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/stretchr/testify/require"
)

func TestDictionaryTokenEfficiencyBypassAllocationBudget(t *testing.T) {
	env, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := env.CompileFilter(
		`filter.failsTokenEfficiency(finding["secret"])`,
		(&detect.Detector{}).Tokenizer(),
	)
	require.NoError(t, err)
	baselineProgram, err := env.CompileFilter(
		`filter.entropy(finding["secret"]) > 0`, nil,
	)
	require.NoError(t, err)
	finding := map[string]any{"secret": "linkedinX9qB2mK7pR4zT8"}

	_, err = env.EvalFilter(program, finding, nil) // Warm Expr and word pools.
	require.NoError(t, err)
	_, err = env.EvalFilter(baselineProgram, finding, nil)
	require.NoError(t, err)
	baselineAllocs := testing.AllocsPerRun(200, func() {
		if _, evalErr := env.EvalFilter(baselineProgram, finding, nil); evalErr != nil {
			panic(evalErr)
		}
	})
	allocs := testing.AllocsPerRun(200, func() {
		if _, evalErr := env.EvalFilter(program, finding, nil); evalErr != nil {
			panic(evalErr)
		}
	})
	// Expr's reflective member/function calls own the baseline allocations; the
	// dictionary fast path must not add token slices or tokenizer regex matches.
	require.LessOrEqual(t, allocs, baselineAllocs+1)
}
