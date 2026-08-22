package sources

import (
	"context"
	"errors"
	"io"
	"maps"
)

// Stdin yields fragments from stdin-like content and applies caller-provided
// attributes before skip filtering and detection.
type Stdin struct {
	Content         io.Reader
	Attributes      map[string]string
	ShouldSkip      SkipFunc
	MaxArchiveDepth int
}

func (s *Stdin) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s == nil {
		return errors.New("sources: stdin source is required")
	}
	if s.Content == nil {
		return errors.New("sources: stdin content is required")
	}
	if yield == nil {
		return errors.New("sources: stdin fragment callback is required")
	}
	file := &File{
		Content:         s.Content,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return file.Fragments(ctx, func(fragment *Fragment, err error) error {
		if len(s.Attributes) > 0 {
			if fragment.Attributes == nil {
				fragment.Attributes = make(map[string]string, len(s.Attributes))
			}
			maps.Copy(fragment.Attributes, s.Attributes)
		}

		if err == nil && s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			fragment.Release()
			return nil
		}

		return yield(fragment, err)
	})
}
