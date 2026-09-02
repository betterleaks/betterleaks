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
			buffer := make([]byte, defaultBufferSize)
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
	// Content is the stream to scan.
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

	return readerFragments(ctx, s.Content, buffer, func(chunk readerChunk, err error) error {
		fragment := chunk.fragment
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

type readerChunk struct {
	fragment Fragment
	// initial aliases the caller-provided read buffer and is valid only for the
	// duration of the callback. File uses it for allocation-free MIME sniffing.
	initial []byte
}

// readerFragments contains the source-neutral mechanics shared by Reader and
// File: buffered reads, safe chunk boundaries, and stream-relative line
// tracking. The caller owns attributes and source-specific policy.
func readerFragments(ctx context.Context, content io.Reader, buffer []byte, yield func(readerChunk, error) error) error {
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
				return yield(readerChunk{fragment: Fragment{StartLine: nextLine}}, readErr)
			}
			return nil
		}

		var raw strings.Builder
		fragmentCapacity := n
		if n == len(buffer) {
			fragmentCapacity += maxPeekSize
		}
		raw.Grow(fragmentCapacity)
		_, _ = raw.Write(buffer[:n])

		var boundaryErr error
		if readErr == nil {
			boundaryErr = readUntilSafeBoundary(reader, n, maxPeekSize, &raw)
			if boundaryErr != nil {
				boundaryErr = fmt.Errorf("could not read until safe boundary: %w", boundaryErr)
			}
		}

		fragment := Fragment{
			Raw:       raw.String(),
			StartLine: nextLine,
		}
		nextLine += strings.Count(fragment.Raw, "\n")
		if err := yield(readerChunk{fragment: fragment, initial: buffer[:n]}, nil); err != nil {
			return err
		}

		if boundaryErr != nil {
			return yield(readerChunk{fragment: Fragment{StartLine: nextLine}}, boundaryErr)
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return yield(readerChunk{fragment: Fragment{StartLine: nextLine}}, readErr)
		}
	}
}

func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

func putBuffer(buffer []byte) {
	buffer = buffer[:cap(buffer)]
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
