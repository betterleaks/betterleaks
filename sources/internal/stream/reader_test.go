package stream

import (
	"bytes"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestReadaheadKeepsChunkBoundaries(t *testing.T) {
	type chunk struct {
		Raw          string
		Line, Column int
	}
	collect := func(content io.Reader) []chunk {
		var chunks []chunk
		require.NoError(t, Read(t.Context(), content, func(raw string, line, column int, err error) error {
			require.NoError(t, err)
			chunks = append(chunks, chunk{raw, line, column})
			return nil
		}))
		return chunks
	}

	// Refills that are not a multiple of 4 KB leave readahead with partial
	// requests to satisfy.
	defer func(size int) {
		readaheadSize = size
		readaheadPool = sync.Pool{New: newReadahead}
	}(readaheadSize)
	readaheadSize = 10_007
	readaheadPool = sync.Pool{New: newReadahead}

	// Blank-line density decides how lookahead ends: the 25 KB budget runs
	// out, or a safe boundary appears early at a varying offset.
	rng := rand.New(rand.NewPCG(1, 2))
	for _, blankLineOdds := range []int{0, 100_000, 5_000, 200} {
		for range 8 {
			data := make([]byte, BufferSize+rng.IntN(4*BufferSize))
			for i := range data {
				data[i] = byte(rng.IntN(256))
				if blankLineOdds > 0 && rng.IntN(blankLineOdds) == 0 && i+1 < len(data) {
					data[i], data[i+1] = '\n', '\n'
				}
			}
			path := filepath.Join(t.TempDir(), "data.bin")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			file, err := os.Open(path)
			require.NoError(t, err)

			// Hide *os.File so the reference takes the direct-read path.
			want := collect(struct{ io.Reader }{bytes.NewReader(data)})
			got := collect(file)
			require.NoError(t, file.Close())
			require.Equal(t, len(want), len(got), "size %d", len(data))
			for i := range want {
				require.Equal(t, want[i], got[i], "size %d chunk %d", len(data), i)
			}
		}
	}
}
