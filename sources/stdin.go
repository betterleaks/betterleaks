package sources

import (
	"context"
	"io"
	"log/slog"
	"maps"
)

// Stdin yields fragments from stdin-like content and applies caller-provided
// attributes before skip filtering and detection.
type Stdin struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger          *slog.Logger
	Content         io.Reader
	Attributes      map[string]string
	ShouldSkip      SkipFunc
	MaxArchiveDepth int
}

func (s *Stdin) Fragments(ctx context.Context, yield FragmentsFunc) error {
	file := &File{
		Logger:          s.Logger,
		Content:         s.Content,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return file.Fragments(ctx, func(fragment Fragment, err error) error {
		if len(s.Attributes) > 0 {
			firstFragment := fragment.Attr(AttrFSFirstFragment)
			if fragment.Attributes == nil {
				fragment.Attributes = make(map[string]string, len(s.Attributes))
			}
			maps.Copy(fragment.Attributes, s.Attributes)
			// AttrFSFirstFragment is owned by the File source and cannot be
			// overridden by caller-provided stdin attributes.
			fragment.SetAttr(AttrFSFirstFragment, firstFragment)
		}

		if err == nil && s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			return nil
		}

		return yield(fragment, err)
	})
}
