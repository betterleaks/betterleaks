package sources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderRequiresContent(t *testing.T) {
	source := &Reader{}
	err := source.Fragments(t.Context(), func(Fragment, error) error {
		t.Fatal("unexpected fragment")
		return nil
	})

	require.EqualError(t, err, "reader content is nil")
}

func TestReaderDoesNotInferProvenance(t *testing.T) {
	source := &Reader{Content: strings.NewReader("token")}

	var fragments []Fragment
	require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	}))

	require.Len(t, fragments, 1)
	assert.Nil(t, fragments[0].Attributes)
	assert.Equal(t, 1, fragments[0].StartLine)
}

func TestReaderCopiesCallerAttributes(t *testing.T) {
	attributes := map[string]string{
		AttrPath:     "response.json",
		AttrResource: "http.response",
	}
	source := &Reader{
		Content:    strings.NewReader("token"),
		Attributes: attributes,
	}

	require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		assert.Equal(t, attributes, fragment.Attributes)
		fragment.Attributes["copy"] = "mutated"
		return nil
	}))
	assert.NotContains(t, attributes, "copy")
}

func TestReaderFragmentsTracksLinesAcrossChunks(t *testing.T) {
	var fragments []Fragment
	err := readerFragments(
		t.Context(),
		strings.NewReader("one\n\ntwo"),
		make([]byte, 3),
		func(chunk readerChunk, err error) error {
			require.NoError(t, err)
			fragments = append(fragments, chunk.fragment)
			return nil
		},
	)
	require.NoError(t, err)
	require.Len(t, fragments, 2)
	assert.Equal(t, Fragment{Raw: "one\n\n", StartLine: 1}, fragments[0])
	assert.Equal(t, Fragment{Raw: "two", StartLine: 3}, fragments[1])
}
