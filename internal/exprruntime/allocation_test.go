//go:build !race

package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExprFilterHotPathAllocations(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	prefilter, err := env.CompilePrefilter(`attributes["path"] == "runtime.go"`)
	require.NoError(t, err)
	_, err = env.EvalPathPrefilter(prefilter, "runtime.go")
	require.NoError(t, err)
	prefilterAllocs := testing.AllocsPerRun(500, func() {
		_, evalErr := env.EvalPathPrefilter(prefilter, "runtime.go")
		if evalErr != nil {
			panic(evalErr)
		}
	})
	// Expr's reflective map member lookup owns one allocation; Betterleaks adds
	// no environment or VM allocation on top of that backend floor.
	require.LessOrEqual(t, prefilterAllocs, 1.0)

	filter, err := env.CompileFilter(`finding["secret"] == "secret" && attributes["path"] == "runtime.go"`, nil)
	require.NoError(t, err)
	finding := map[string]any{"secret": "secret"}
	attributes := map[string]string{"path": "runtime.go"}
	_, err = env.EvalFilter(filter, finding, attributes)
	require.NoError(t, err)
	filterAllocs := testing.AllocsPerRun(500, func() {
		_, evalErr := env.EvalFilter(filter, finding, attributes)
		if evalErr != nil {
			panic(evalErr)
		}
	})
	// The two map member lookups each allocate once inside Expr's reflection
	// path. The reusable VM and bindings add no further hot-path allocations.
	require.LessOrEqual(t, filterAllocs, 2.0)
}

func TestReleaseBindingsDoesNotRetainVMValues(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	program, err := env.CompileFilter(`finding["secret"] == "secret"`, nil)
	require.NoError(t, err)

	eval := program.acquireBindings()
	eval.machine.Stack = append(eval.machine.Stack, "stack value")
	eval.machine.Variables = append(eval.machine.Variables, "local value")
	// Expr pops its result by shortening Stack, so retention tests must cover
	// references hidden beyond the current slice length as well.
	eval.machine.Stack = eval.machine.Stack[:0]
	eval.machine.Variables = eval.machine.Variables[:0]
	program.releaseBindings(eval)

	eval = program.acquireBindings()
	defer program.releaseBindings(eval)
	for _, value := range eval.machine.Stack[:cap(eval.machine.Stack)] {
		require.Nil(t, value)
	}
	for _, value := range eval.machine.Variables[:cap(eval.machine.Variables)] {
		require.Nil(t, value)
	}
}
