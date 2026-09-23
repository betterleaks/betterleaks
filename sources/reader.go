package sources

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"
)

const defaultBufferSize = 100 * 1_000 // 100 KB

var (
	bufferPool = sync.Pool{
		New: func() any {
			// Keep lookahead in the same reusable backing array as the initial
			// read. Fragment.Raw receives one exact-sized string copy before the
			// buffer returns to the pool.
			buffer := make([]byte, defaultBufferSize, defaultBufferSize+maxPeekSize)
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

// Reader yields fragments from arbitrary text read from Content. It does not
// infer a resource type or other provenance; callers can supply that context
// through Attributes.
type Reader struct {
	// Content is the stream to scan. Reader does not close it. The caller must
	// cancel or close the underlying reader to interrupt a blocked Read;
	// context cancellation alone cannot interrupt an arbitrary io.Reader.
	Content io.Reader
	// Attributes are copied onto every fragment yielded from Content.
	Attributes map[string]string
	// ShouldSkip decides whether to discard a fragment from Content.
	ShouldSkip SkipFunc
}

func (s *Reader) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s == nil || s.Content == nil {
		return errors.New("reader content is nil")
	}

	buffer := getBuffer()
	defer putBuffer(buffer)

	return readerFragments(ctx, s.Content, buffer, func(fragment Fragment, err error) error {
		if len(s.Attributes) > 0 {
			fragment.Attributes = make(map[string]string, len(s.Attributes))
			maps.Copy(fragment.Attributes, s.Attributes)
		}

		if err != nil {
			return yield(fragment, fmt.Errorf("could not read reader: %w", err))
		}
		if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			return nil
		}
		return yield(fragment, nil)
	})
}

// readerFragments contains the source-neutral mechanics shared by Reader and
// File: buffered reads, safe chunk boundaries, and stream-relative line
// tracking. The caller owns attributes and source-specific policy.
func readerFragments(ctx context.Context, content io.Reader, buffer []byte, yield FragmentsFunc) error {
	if len(buffer) == 0 {
		return errors.New("reader buffer is empty")
	}

	reader := getReader(content)
	defer putReader(reader)

	nextLine := 1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := reader.Read(buffer)
		if n == 0 {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return yield(Fragment{StartLine: nextLine}, readErr)
			}
			return nil
		}

		chunk := buffer[:n]

		var boundaryErr error
		if readErr == nil {
			chunk, boundaryErr = readUntilSafeBoundary(reader, chunk, n, maxPeekSize)
		}

		fragment := Fragment{
			Raw:       string(chunk),
			StartLine: nextLine,
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}

		if errors.Is(boundaryErr, io.EOF) || errors.Is(readErr, io.EOF) {
			return ctx.Err()
		}
		nextLine += strings.Count(fragment.Raw, "\n")
		if boundaryErr != nil {
			return yield(Fragment{StartLine: nextLine}, fmt.Errorf("could not read until safe boundary: %w", boundaryErr))
		}
		if readErr != nil {
			return yield(Fragment{StartLine: nextLine}, readErr)
		}
	}
}

func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

func putBuffer(buffer []byte) {
	buffer = buffer[:defaultBufferSize]
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
