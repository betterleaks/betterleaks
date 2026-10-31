// Package stream provides buffered text chunks with stable ownership and line numbers.
package stream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
)

// Read yields owned text chunks, one-based starting lines, and the zero-based
// byte offset of each chunk on its first line. Read failures are
// yielded after any final bytes; a callback error stops reading immediately.
// The caller owns content and must interrupt any blocked Read itself.
func Read(ctx context.Context, content io.Reader, yield func(string, int, int, error) error) error {
	buffer := getBuffer()
	defer putBuffer(buffer)
	return read(ctx, content, buffer, yield)
}

func read(ctx context.Context, content io.Reader, buffer []byte, yield func(string, int, int, error) error) error {
	if len(buffer) == 0 {
		return errors.New("reader buffer is empty")
	}

	reader := getReader(content)
	defer putReader(reader)

	nextLine := 1
	nextColumnOffset := 0
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
		nextLine += strings.Count(raw, "\n")
		if lastNewline := strings.LastIndexByte(raw, '\n'); lastNewline >= 0 {
			nextColumnOffset = len(raw) - lastNewline - 1
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

func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

func putBuffer(buffer []byte) {
	buffer = buffer[:BufferSize]
	bufferPool.Put(&buffer)
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
