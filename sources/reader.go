package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
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
	// Prefilter decides whether to discard a fragment from Content.
	Prefilter SkipFunc
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
		if s.Prefilter != nil && s.Prefilter(fragment.Attributes) {
			return nil
		}
		return yield(fragment, nil)
	})
}

// readerFragments applies v1 safe chunk boundaries and stream-relative line
// tracking to text streams. The caller owns attributes and filtering.
func readerFragments(ctx context.Context, content io.Reader, buffer []byte, yield FragmentsFunc) error {
	if len(buffer) == 0 {
		return errors.New("reader buffer is empty")
	}

	reader := getReader(content)
	defer putReader(reader)

	nextLine := 1
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := reader.Read(buffer)
		if n == 0 {
			if readErr == nil {
				// Match bufio's bounded retries without treating an empty read as EOF.
				emptyReads++
				if emptyReads >= 100 {
					return yield(Fragment{StartLine: nextLine}, io.ErrNoProgress)
				}
				continue
			}
			if !errors.Is(readErr, io.EOF) {
				return yield(Fragment{StartLine: nextLine}, readErr)
			}
			return ctx.Err()
		}
		emptyReads = 0

		chunk := buffer[:n]

		var boundaryErr error
		if readErr == nil {
			peek := bytes.NewBuffer(chunk)
			boundaryErr = readUntilSafeBoundary(reader, n, maxPeekSize, peek)
			chunk = peek.Bytes()
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
