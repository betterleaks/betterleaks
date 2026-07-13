package exprruntime

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterNearMatchHelpers(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	finding := map[string]string{"secret": "SECRET"}
	window := MatchWindow{
		Raw:        "prefix provider SECRET trailing",
		MatchStart: len("prefix provider "),
		MatchEnd:   len("prefix provider SECRET"),
	}

	t.Run("contains before match", func(t *testing.T) {
		prg, err := env.CompileFilter(`filter.containsAnyNearMatch(finding, ["provider"], 20, 0)`, nil)
		require.NoError(t, err)

		got, err := env.EvalFilterWithMatchWindow(prg, finding, nil, window)
		require.NoError(t, err)
		require.True(t, got)
	})

	t.Run("matches after match", func(t *testing.T) {
		prg, err := env.CompileFilter("filter.matchesAnyNearMatch(finding, [`trailing$`], 0, 10, false)", nil)
		require.NoError(t, err)

		got, err := env.EvalFilterWithMatchWindow(prg, finding, nil, window)
		require.NoError(t, err)
		require.True(t, got)
	})

	t.Run("respects window bounds", func(t *testing.T) {
		prg, err := env.CompileFilter(`filter.containsAnyNearMatch(finding, ["prefix"], 5, 0)`, nil)
		require.NoError(t, err)

		got, err := env.EvalFilterWithMatchWindow(prg, finding, nil, window)
		require.NoError(t, err)
		require.False(t, got)
	})

	t.Run("stays on match line", func(t *testing.T) {
		raw := "before\nprovider SECRET trailing\nafter"
		window := MatchWindow{Raw: raw, MatchStart: len("before\nprovider "), MatchEnd: len("before\nprovider SECRET")}
		for _, tc := range []struct {
			pattern     string
			limitToLine bool
			want        bool
		}{
			{"before", true, false},
			{"after", true, false},
			{"before", false, true},
		} {
			prg, err := env.CompileFilter(`filter.matchesAnyNearMatch(finding, ["`+tc.pattern+`"], 100, 100, `+strconv.FormatBool(tc.limitToLine)+`)`, nil)
			require.NoError(t, err)
			got, err := env.EvalFilterWithMatchWindow(prg, finding, nil, window)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		}
	})
}

func TestFilterNearMatchBounds(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	maxInt := strconv.Itoa(math.MaxInt)

	tests := []struct {
		name   string
		expr   string
		window MatchWindow
		want   bool
	}{
		{"clamps both ends", `filter.containsAnyNearMatch(finding, ["prefix", "suffix"], ` + maxInt + `, ` + maxInt + `)`, MatchWindow{Raw: "prefix SECRET suffix", MatchStart: 7, MatchEnd: 13}, true},
		{"negative becomes zero", `filter.containsAnyNearMatch(finding, ["prefix"], -1, -1)`, MatchWindow{Raw: "prefix SECRET", MatchStart: 7, MatchEnd: 13}, false},
		{"empty", `filter.containsAnyNearMatch(finding, ["prefix"], 10, 10)`, MatchWindow{}, false},
		{"invalid", `filter.containsAnyNearMatch(finding, ["prefix"], 10, 10)`, MatchWindow{Raw: "short", MatchStart: -1, MatchEnd: math.MaxInt}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := env.CompileFilter(tt.expr, nil)
			require.NoError(t, err)
			got, err := env.EvalFilterWithMatchWindow(prg, nil, nil, tt.window)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilterEvalBindingsDoNotShareRuntimeState(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	prg, err := env.CompileFilter(`filter.containsAnyNearMatch(finding, ["provider"], 20, 0)`, nil)
	require.NoError(t, err)

	a := prg.evalBindings()
	b := prg.evalBindings()

	rtA, ok := a["__runtime"].(*runtimeBindings)
	require.True(t, ok)
	rtB, ok := b["__runtime"].(*runtimeBindings)
	require.True(t, ok)
	require.NotSame(t, rtA, rtB)

	rtA.matchWindow = MatchWindow{Raw: "provider SECRET", MatchStart: len("provider "), MatchEnd: len("provider SECRET")}
	rtB.matchWindow = MatchWindow{Raw: "other SECRET", MatchStart: len("other "), MatchEnd: len("other SECRET")}

	filterA := a["filter"].(map[string]any)
	filterB := b["filter"].(map[string]any)
	containsA := filterA["containsAnyNearMatch"].(func(any, any, int, int) bool)
	containsB := filterB["containsAnyNearMatch"].(func(any, any, int, int) bool)

	require.True(t, containsA(nil, []string{"provider"}, 20, 0))
	require.False(t, containsB(nil, []string{"provider"}, 20, 0))
}
