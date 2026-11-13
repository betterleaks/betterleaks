package codec

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeBudgetStopsBeforeCollectingAllSegments(t *testing.T) {
	stop := errors.New("allocation budget exhausted")
	calls := 0
	decoded, segments, err := DecodeWithBudget(strings.Repeat("%41\n", 10000), nil, func(int64) error {
		calls++
		if calls == 3 {
			return stop
		}
		return nil
	})
	require.ErrorIs(t, err, stop)
	require.Empty(t, decoded)
	require.Nil(t, segments)
	require.Equal(t, 3, calls)
}

func TestDecodeBudgetPreservesResults(t *testing.T) {
	for _, input := range []string{"", "plain text", "%41%42%43", `\u0041\u0042`, "c2VjcmV0LWFscGhh", "6162636465666768696a6b6c6d6e6f70"} {
		want, wantSegments := Decode(input, nil)
		got, gotSegments, err := DecodeWithBudget(input, nil, func(int64) error { return nil })
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, wantSegments, gotSegments)
	}
}
