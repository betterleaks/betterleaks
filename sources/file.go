package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
	"github.com/mholt/archives"
)

const InnerPathSeparator = "!"

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger *slog.Logger
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// ShouldSkip is a callback that decides whether to skip a file based on its
	// attributes (e.g. path). If nil, no skipping is performed.
	ShouldSkip SkipFunc
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// archiveDepth is the current archive nesting depth
	archiveDepth int
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	var err error
	var format archives.Format
	stream := s.Content

	// tar files can sometimes be compressed without having the compression
	// in their file extension name. Even though it is common to have the
	// compression in the name, the tar command can still determine if
	// the file is compressed. So in cases where we're working with tar files
	// that don't have a compression extension in the name, we should go
	// ahead and check the content itself to see if it's compressed
	if filepath.Ext(s.Path) == ".tar" {
		format, stream, err = archives.Identify(ctx, s.Path, stream)
	} else {
		format, _, err = archives.Identify(ctx, s.Path, nil)
	}

	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				loggerOrDiscard(s.Logger).Warn("skipping archive: exceeds max archive depth",
					"path", s.FullPath(),
					"max_archive_depth", s.MaxArchiveDepth,
				)
			} else {
				logTrace(ctx, s.Logger, "skipping archive: exceeds max archive depth",
					"path", s.FullPath(),
					"max_archive_depth", s.MaxArchiveDepth,
				)
			}
			return nil
		}
		if extractor, ok := format.(archives.Extractor); ok {
			s.extractorFragments(ctx, extractor, stream, yield)
			return nil
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			s.decompressorFragments(ctx, decompressor, stream, yield)
			return nil
		}
		loggerOrDiscard(s.Logger).Warn("skipping unknown archive type", "path", s.FullPath())
	}

	isArchiveContent := s.archiveDepth > 0
	return s.fileFragments(ctx, stream, isArchiveContent, yield)
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) {
	// Malformed archives can make the extraction library panic (e.g. a tiny
	// .rar whose block header encodes a bogus size). Recover here so a bad
	// archive is skipped with a warning instead of killing the process. This
	// guard sits inside extractorFragments (rather than at the dispatch site)
	// so it protects every nesting level: extractorFragments recurses into
	// nested entries via file.Fragments below.
	defer func() {
		if r := recover(); r != nil {
			loggerOrDiscard(s.Logger).Warn("skipping archive: panic during extraction", "path", s.FullPath(), "panic", fmt.Sprint(r))
		}
	}()

	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "betterleaks-archive-")
			if err != nil {
				loggerOrDiscard(s.Logger).Warn("could not create archive tmp file", "error", err, "path", s.FullPath())
				return
			}
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				loggerOrDiscard(s.Logger).Warn("could not copy archive file", "error", err, "path", s.FullPath())
				return
			}

			reader = tmpfile
		}
	}

	err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		path := filepath.Clean(d.NameInArchive)
		if !d.Mode().IsRegular() {
			logTrace(ctx, s.Logger, "skipping non-regular file", "path", path)
			return nil
		}

		innerReader, err := d.Open()
		if err != nil {
			loggerOrDiscard(s.Logger).Warn("could not open archive inner file", "error", err, "path", s.FullPath())
			return nil
		}
		defer innerReader.Close()

		if s.ShouldSkip != nil && shouldSkipPath(s.ShouldSkip, path) {
			loggerOrDiscard(s.Logger).Debug("skipping file: global prefilter", "path", s.FullPath())
			return nil
		}

		file := &File{
			Logger:          s.Logger,
			Content:         innerReader,
			Path:            path,
			Symlink:         s.Symlink,
			ShouldSkip:      s.ShouldSkip,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
		}

		return file.Fragments(ctx, yield)
	})

	if err != nil {
		loggerOrDiscard(s.Logger).Warn("error reading archive", "error", err, "path", s.FullPath())
	}
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) {
	// Register recovery before cleanup so it runs last and can also catch a
	// panic from closing a malformed decompressor reader.
	defer func() {
		if r := recover(); r != nil {
			loggerOrDiscard(s.Logger).Warn("skipping compressed file: panic during decompression", "path", s.FullPath(), "panic", fmt.Sprint(r))
		}
	}()

	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		loggerOrDiscard(s.Logger).Warn("could not read compressed file", "error", err, "path", s.FullPath())
		return
	}
	defer func() {
		_ = innerReader.Close()
	}()

	if err := s.fileFragments(ctx, innerReader, true, yield); err != nil {
		loggerOrDiscard(s.Logger).Warn("error reading compressed file", "error", err, "path", s.FullPath())
	}
}

var errStopFileFragments = errors.New("stop file fragments")

// fileFragments adds filesystem policy and metadata to source-neutral reader
// fragments.
func (s *File) fileFragments(ctx context.Context, content io.Reader, isArchiveContent bool, yield FragmentsFunc) error {
	// Use a pooled buffer if the caller hasn't provided one.
	if s.Buffer == nil {
		s.Buffer = getBuffer()
		defer func() {
			putBuffer(s.Buffer)
			s.Buffer = nil
		}()
	}

	fullPath := s.FullPath()
	fragmentPath := fullPath
	if isWindows {
		fragmentPath = filepath.ToSlash(fullPath)
	}
	firstFragment := true

	err := readerFragments(ctx, content, s.Buffer, func(chunk readerChunk, readErr error) error {
		fragment := chunk.fragment
		first := "false"
		if firstFragment {
			first = "true"
		}
		fragment.Attributes = map[string]string{
			AttrPath:            fragmentPath,
			AttrResource:        ResourceFileContent,
			AttrFSFirstFragment: first,
		}

		if readErr != nil {
			if isArchiveContent {
				loggerOrDiscard(s.Logger).Warn("could not read archive content", "error", readErr, "path", fullPath)
				return nil
			}
			return yield(fragment, fmt.Errorf("could not read file: %w", readErr))
		}

		// MIME detection is filesystem policy. Reader intentionally scans the
		// text it is given without trying to classify the underlying resource.
		if firstFragment {
			mimetype, matchErr := filetype.Match(chunk.initial)
			if matchErr != nil {
				if isArchiveContent {
					loggerOrDiscard(s.Logger).Warn("could not determine archive content type", "error", matchErr, "path", fullPath)
					return errStopFileFragments
				}
				if err := yield(fragment, fmt.Errorf("could not read file: could not determine type: %w", matchErr)); err != nil {
					return err
				}
				return errStopFileFragments
			}
			if mimetype.MIME.Type == "application" {
				loggerOrDiscard(s.Logger).Debug("skipping binary file", "mime_type", mimetype.MIME.Value, "path", fullPath)
				return errStopFileFragments
			}
		}

		if s.Symlink != "" {
			symlink := s.Symlink
			if isWindows {
				symlink = filepath.ToSlash(symlink)
			}
			fragment.SetAttr(AttrFSSymlink, symlink)
		}

		firstFragment = false
		return yield(fragment, nil)
	})
	if errors.Is(err, errStopFileFragments) {
		return nil
	}
	return err
}

// FullPath returns the File.Path with any preceding outer paths
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		return strings.Join(
			// outerPaths have already been normalized to slash
			append(s.outerPaths, s.Path),
			InnerPathSeparator,
		)
	}

	return s.Path
}
