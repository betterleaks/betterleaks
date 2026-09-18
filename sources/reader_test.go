package sources

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

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

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestReaderDoesNotRediscoverEOF(t *testing.T) {
	for _, input := range []string{"small file", "small file\n\n", ""} {
		t.Run(input, func(t *testing.T) {
			content := strings.NewReader(input)
			reads := 0
			source := &Reader{Content: readerFunc(func(p []byte) (int, error) {
				reads++
				return content.Read(p)
			})}
			var got strings.Builder
			require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
				got.WriteString(fragment.Raw)
				return err
			}))
			require.Equal(t, input, got.String())
			wantReads := 2 // One data read and one EOF read.
			if input == "" {
				wantReads = 1
			}
			require.Equal(t, wantReads, reads)
		})
	}
}

func TestReaderShortReadsPreserveFragments(t *testing.T) {
	source := &Reader{Content: iotest.OneByteReader(strings.NewReader("one\n\ntwo"))}
	var fragments []Fragment
	require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)
		return err
	}))
	require.Equal(t, []Fragment{{Raw: "one\n\n", StartLine: 1}, {Raw: "two", StartLine: 3}}, fragments)
}

func TestReaderYieldsFinalBytesBeforeReadError(t *testing.T) {
	readFailure := errors.New("read failed")
	for _, readErr := range []error{io.EOF, readFailure} {
		for _, withData := range []bool{false, true} {
			input := "one\ntwo"
			reads := 0
			source := &Reader{Content: readerFunc(func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					n := copy(p, input)
					if withData {
						return n, readErr
					}
					return n, nil
				}
				return 0, readErr
			})}
			var fragments []Fragment
			var reported []error
			err := source.Fragments(t.Context(), func(fragment Fragment, err error) error {
				fragments = append(fragments, fragment)
				reported = append(reported, err)
				return err
			})
			require.NotEmpty(t, fragments)
			require.Equal(t, Fragment{Raw: input, StartLine: 1}, fragments[0])
			require.NoError(t, reported[0])
			if readErr == io.EOF {
				require.NoError(t, err)
				require.Len(t, fragments, 1)
			} else {
				require.ErrorIs(t, err, readFailure)
				require.Len(t, fragments, 2)
				require.Equal(t, Fragment{StartLine: 2}, fragments[1])
				require.ErrorIs(t, reported[1], readFailure)
			}
		}
	}
}

func TestReaderPreservesCallbackFailureAndCancellationAtEOF(t *testing.T) {
	callbackErr := errors.New("callback failed")
	source := &Reader{Content: strings.NewReader("small file")}
	err := source.Fragments(t.Context(), func(Fragment, error) error { return callbackErr })
	require.ErrorIs(t, err, callbackErr)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source.Content = strings.NewReader("small file")
	err = source.Fragments(ctx, func(Fragment, error) error {
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
}
