package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/betterleaks/betterleaks/v2/sources/internal/stream"
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
	Prefilter PrefilterFunc
}

func (s *Reader) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s == nil || s.Content == nil {
		return errors.New("reader content is nil")
	}

	return stream.Read(ctx, s.Content, func(raw string, line, columnOffset int, err error) error {
		fragment := Fragment{Raw: raw, StartLine: line, StartColumnOffset: columnOffset}
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
