package stream

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderFragmentsTracksLinesAcrossChunks(t *testing.T) {
	type chunk struct {
		Raw       string
		StartLine int
	}
	var fragments []chunk
	err := read(
		t.Context(),
		strings.NewReader("one\n\ntwo"),
		make([]byte, 3),
		func(raw string, line, _ int, err error) error {
			fragment := chunk{Raw: raw, StartLine: line}
			require.NoError(t, err)
			fragments = append(fragments, fragment)
			return nil
		},
	)
	require.NoError(t, err)
	require.Len(t, fragments, 2)
	assert.Equal(t, chunk{Raw: "one\n\n", StartLine: 1}, fragments[0])
	assert.Equal(t, chunk{Raw: "two", StartLine: 3}, fragments[1])
}
