package sources

import (
	"context"
	"io"
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
	file := &File{
		Content:         s.Content,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return file.Fragments(ctx, func(fragment Fragment, err error) error {
		if len(s.Attributes) > 0 {
			if fragment.Attributes == nil {
				fragment.Attributes = make(map[string]string, len(s.Attributes))
			}
			for key, value := range s.Attributes {
				fragment.Attributes[key] = value
			}
		}

		if err == nil && s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			return nil
		}

		return yield(fragment, err)
	})
}
