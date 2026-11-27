// Package stream provides buffered text chunks with stable ownership and line numbers.
package stream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// BufferSize is the initial number of bytes read for each chunk.
const BufferSize = 100 * 1_000 // 100 KB

var (
	bufferPool = sync.Pool{
		New: func() any {
			// Keep lookahead in the same reusable backing array as the initial
			// read. Each chunk receives one exact-sized string copy before the
			// buffer returns to the pool.
			buffer := make([]byte, BufferSize, BufferSize+maxPeekSize)
			return &buffer
		},
	}
	readerPool = sync.Pool{
		New: func() any {
			// Match bufio.NewReader's default size to preserve chunk boundaries
			// when readUntilSafeBoundary reads ahead.
			return bufio.NewReader(nil)
		},
	}
	readaheadPool = sync.Pool{New: newReadahead}
)

// readaheadSize is the read size for files longer than one chunk. Lookahead
// otherwise costs a read syscall for every 4 KB the boundary search consumes.
// Tests change it to misalign buffer refills.
var readaheadSize = 256 << 10

func newReadahead() any {
	return bufio.NewReaderSize(nil, readaheadSize)
}

// fullReader fills each request unless its source ends, as regular file reads
// do. The 4 KB reader above it therefore keeps the same chunk boundaries.
type fullReader struct{ reader *bufio.Reader }

func (r fullReader) Read(p []byte) (int, error) {
	n, err := io.ReadFull(r.reader, p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}

// readahead reports whether content is a regular file. Pipes and other
// streams keep returning whatever bytes are available.
func readahead(content io.Reader) (*os.File, bool) {
	file, ok := content.(*os.File)
	if !ok {
		return nil, false
	}
	info, err := file.Stat()
	return file, err == nil && info.Mode().IsRegular()
}

// Read yields owned text chunks, one-based starting lines, and the zero-based
// byte offset of each chunk on its first line. Read failures are
// yielded after any final bytes; a callback error stops reading immediately.
// The caller owns content and must interrupt any blocked Read itself.
func Read(ctx context.Context, content io.Reader, yield func(string, int, int, error) error) error {
	buffer := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(buffer)
	return read(ctx, content, *buffer, yield)
}

func read(ctx context.Context, content io.Reader, buffer []byte, yield func(string, int, int, error) error) error {
	if len(buffer) == 0 {
		return errors.New("reader buffer is empty")
	}

	reader := getReader(content)
	defer putReader(reader)

	nextLine := 1
	nextColumnOffset := 0
	firstRead := true
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := reader.Read(buffer)
		if n == 0 {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return yield("", nextLine, 0, readErr)
			}
			return nil
		}
		// A full first read bypassed the empty 4 KB buffer, so swapping its
		// source here drops nothing. Smaller files keep direct reads.
		if firstRead && n == len(buffer) && readErr == nil {
			if file, ok := readahead(content); ok {
				ahead := readaheadPool.Get().(*bufio.Reader)
				ahead.Reset(file)
				defer func() {
					ahead.Reset(nil)
					readaheadPool.Put(ahead)
				}()
				reader.Reset(fullReader{ahead})
			}
		}
		firstRead = false

		chunk := buffer[:n]

		var boundaryErr error
		if readErr == nil {
			chunk, boundaryErr = readUntilSafeBoundary(reader, chunk, n, maxPeekSize)
		}

		raw := string(chunk)
		if err := yield(raw, nextLine, nextColumnOffset, nil); err != nil {
			return err
		}

		if errors.Is(boundaryErr, io.EOF) || errors.Is(readErr, io.EOF) {
			return ctx.Err()
		}
		if lines := strings.Count(raw, "\n"); lines > 0 {
			nextLine += lines
			nextColumnOffset = len(raw) - strings.LastIndexByte(raw, '\n') - 1
		} else {
			nextColumnOffset += len(raw)
		}
		if boundaryErr != nil {
			return yield("", nextLine, 0, fmt.Errorf("could not read until safe boundary: %w", boundaryErr))
		}
		if readErr != nil {
			return yield("", nextLine, 0, readErr)
		}
	}
}

func getReader(reader io.Reader) *bufio.Reader {
	buffered := readerPool.Get().(*bufio.Reader)
	buffered.Reset(reader)
	return buffered
}

func putReader(reader *bufio.Reader) {
	reader.Reset(nil)
	readerPool.Put(reader)
}
