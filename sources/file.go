package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/h2non/filetype"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"

	"github.com/betterleaks/betterleaks/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, defaultBufferSize)
		return &buf
	},
}

func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

func putBuffer(buf []byte) {
	buf = buf[:cap(buf)]
	bufferPool.Put(&buf)
}

var readerPool = sync.Pool{
	New: func() any {
		// Use the same default size as bufio.NewReader (4096) to preserve
		// chunk boundary behavior in readUntilSafeBoundary.
		return bufio.NewReader(nil)
	},
}

func getReader(r io.Reader) *bufio.Reader {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func putReader(br *bufio.Reader) {
	br.Reset(nil)
	readerPool.Put(br)
}

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Logger receives source diagnostics. A nil logger uses the configured application logger.
	Logger *zerolog.Logger
	// Content is the stream to scan. File does not close it. The caller owns
	// the reader and must interrupt any blocked Read when canceling.
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Attributes supply source metadata, including an optional resource override.
	// Path and archive entry paths are always derived from Path.
	Attributes map[string]string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading content in chunks.
	Buffer []byte
	// ShouldSkip is a callback that decides whether to skip a file based on its
	// attributes (e.g. path). If nil, no skipping is performed.
	ShouldSkip SkipFunc
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// DetectArchive also identifies archives by content, for downloads whose
	// paths do not have a filename extension. Inherited by nested archive entries.
	DetectArchive bool
	// StrictArchives reports archive read failures and depth limits through
	// yield, marking coverage incomplete instead of only logging a warning.
	StrictArchives bool
	// ScanBinary includes recognized binary files instead of applying v1 filesystem skips.
	ScanBinary bool
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// archiveDepth is the current archive nesting depth
	archiveDepth int
	// decompressed keeps a compressed filename from identifying its already
	// decoded stream as the same format again. Inspect this stream by content.
	decompressed bool
}

func (s *File) logger() *zerolog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return &logging.Logger
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Attributes != nil && s.ShouldSkip != nil && s.ShouldSkip(s.attributes(s.FullPath())) {
		return nil
	}
	// Archive walkers may log errors. Preserve callback errors for every caller.
	var yieldErr error
	emit := yield
	yield = func(fragment Fragment, err error) error {
		if yieldErr != nil {
			return yieldErr
		}
		if err == nil && s.Attributes != nil && s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			return nil
		}
		yieldErr = emit(fragment, err)
		return yieldErr
	}
	defer func() {
		if yieldErr != nil {
			err = yieldErr
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
	var format archives.Format
	stream := s.Content
	archiveName := s.Path
	if ext := filepath.Ext(archiveName); strings.EqualFold(ext, ".tgz") {
		// The archive library's filename matching requires .tar.gz. Keep the
		// original path for prefilters and finding attribution.
		archiveName = strings.TrimSuffix(archiveName, ext) + ".tar.gz"
	}

	// Downloads may have opaque names. Local .tar files also need content
	// inspection because their compression is not always reflected in the name.
	if s.DetectArchive {
		format, stream, err = archives.Identify(ctx, "", stream)
		if errors.Is(err, archives.NoMatch) && !s.decompressed {
			format, _, err = archives.Identify(ctx, archiveName, nil)
		}
	} else if filepath.Ext(s.Path) == ".tar" {
		format, stream, err = archives.Identify(ctx, s.Path, stream)
	} else {
		format, _, err = archives.Identify(ctx, archiveName, nil)
	}

	if s.StrictArchives && err != nil && !errors.Is(err, archives.NoMatch) {
		return yield(Fragment{}, fmt.Errorf("identify archive %q: %w", s.FullPath(), err))
	}

	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			if s.StrictArchives {
				return yield(Fragment{}, fmt.Errorf("archive %q exceeds max archive depth %d", s.FullPath(), s.MaxArchiveDepth))
			}
			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				s.logger().Warn().Str("path", s.FullPath()).Int("max_archive_depth", s.MaxArchiveDepth).Msg("skipping archive: exceeds max archive depth")
			} else {
				s.logger().Trace().Str("path", s.FullPath()).Int("max_archive_depth", s.MaxArchiveDepth).Msg("skipping archive: exceeds max archive depth")
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
		s.logger().Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
		if s.StrictArchives {
			return yield(Fragment{}, fmt.Errorf("unsupported archive type at %q", s.FullPath()))
		}
	}

	isArchiveContent := s.archiveDepth > 0
	br := getReader(stream)
	defer putReader(br)
	return s.fileFragments(ctx, br, isArchiveContent, yield)
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
			s.logger().Warn().Str("path", s.FullPath()).Str("panic", fmt.Sprint(r)).Msg("skipping archive: panic during extraction")
			s.archiveFailure(yield, fmt.Errorf("archive extraction panic: %v", r))
		}
	}()

	// CompressedArchive stops at the inner archive's EOF, which may precede
	// the compression checksum. In strict mode own the decoder and drain it.
	if compressed, ok := extractor.(archives.CompressedArchive); ok && s.StrictArchives {
		inner, err := compressed.Compression.OpenReader(reader)
		if err != nil {
			s.archiveFailure(yield, err)
			return
		}
		var stopped error
		emit := yield
		yield = func(fragment Fragment, err error) error {
			if stopped == nil {
				stopped = emit(fragment, err)
			}
			return stopped
		}
		defer func() {
			if err := inner.Close(); err != nil && stopped == nil {
				s.archiveFailure(yield, err)
			}
		}()
		defer func() {
			if stopped == nil && ctx.Err() == nil {
				if err := drainArchive(ctx, inner); err != nil {
					s.archiveFailure(yield, err)
				}
			}
		}()
		extractor, reader = compressed.Extraction, inner
	}

	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "betterleaks-archive-")
			if err != nil {
				s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("could not create archive tmp file")
				s.archiveFailure(yield, err)
				return
			}
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("could not copy archive file")
				s.archiveFailure(yield, err)
				return
			}

			reader = tmpfile
		}
	}

	err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		path := filepath.Clean(d.NameInArchive)
		if !d.Mode().IsRegular() {
			s.logger().Trace().Str("path", path).Msg("skipping non-regular file")
			return nil
		}

		innerReader, err := d.Open()
		if err != nil {
			s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("could not open archive inner file")
			return s.archiveFailure(yield, err)
		}
		defer innerReader.Close()

		if s.ShouldSkip != nil && shouldSkipPath(func(attrs map[string]string) bool {
			return s.ShouldSkip(s.attributes(attrs[AttrPath]))
		}, path) {
			s.logger().Debug().Str("path", s.FullPath()).Msg("skipping file: global prefilter")
			return nil
		}

		file := &File{
			Logger:          s.Logger,
			Content:         innerReader,
			Path:            path,
			Attributes:      s.Attributes,
			Symlink:         s.Symlink,
			ShouldSkip:      s.ShouldSkip,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			DetectArchive:   s.DetectArchive,
			StrictArchives:  s.StrictArchives,
			ScanBinary:      s.ScanBinary,
			archiveDepth:    s.archiveDepth + 1,
		}

		return file.Fragments(ctx, yield)
	})

	if err != nil {
		s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("error reading archive")
		s.archiveFailure(yield, err)
	}
}

// decompressorFragments inspects each decoded stream for further archives or
// compression. A compression-only wrapper consumes one archive-depth level.
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) {
	// Register recovery before cleanup so it runs last and can also catch a
	// panic from closing a malformed decompressor reader.
	defer func() {
		if r := recover(); r != nil {
			s.logger().Warn().Str("path", s.FullPath()).Str("panic", fmt.Sprint(r)).Msg("skipping compressed file: panic during decompression")
			s.archiveFailure(yield, fmt.Errorf("archive decompression panic: %v", r))
		}
	}()

	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("could not read compressed file")
		s.archiveFailure(yield, err)
		return
	}
	defer func() {
		if err := innerReader.Close(); err != nil {
			s.archiveFailure(yield, err)
		}
	}()

	inner := *s
	inner.Content = innerReader
	inner.archiveDepth++
	inner.DetectArchive = true
	inner.decompressed = true
	if err := inner.Fragments(ctx, yield); err != nil {
		s.logger().Warn().Err(err).Str("path", s.FullPath()).Msg("error reading compressed file")
		s.archiveFailure(yield, err)
		return
	}
	if s.StrictArchives && ctx.Err() == nil {
		if err := drainArchive(ctx, innerReader); err != nil {
			s.archiveFailure(yield, err)
		}
	}
}

// Drain through Read, not an optional WriterTo fast path. In particular, LZ4's
// WriterTo returns EOF as an error after Read has exhausted the stream. Read
// also retains any partially consumed decoder buffer when checking trailers.
func drainArchive(ctx context.Context, reader io.Reader) error {
	_, err := io.Copy(io.Discard, archiveDrainReader{ctx: ctx, reader: reader})
	return err
}

type archiveDrainReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r archiveDrainReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *File) archiveFailure(yield FragmentsFunc, err error) error {
	if s.StrictArchives {
		// Fragments' wrapper retains callback errors, including errors returned
		// inside the archive library's callback or panic recovery.
		return yield(Fragment{}, fmt.Errorf("archive %q: %w", s.FullPath(), err))
	}
	return nil
}

// fileFragments reads the file into fragments to yield.
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, isArchiveContent bool, yield FragmentsFunc) error {
	// Use a pooled buffer if the caller hasn't provided one.
	if s.Buffer == nil {
		s.Buffer = getBuffer()
		defer func() {
			putBuffer(s.Buffer)
			s.Buffer = nil
		}()
	}

	prevFragmentEndLine := 0
	firstFragmentAttr := "true"
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Compute the final normalized path upfront (isWindows is a compile-time constant).
			fullPath := s.FullPath()
			fragPath := fullPath
			if isWindows {
				fragPath = filepath.ToSlash(fullPath)
			}
			attr := s.attributes(fragPath)
			attr[AttrFSFirstFragment] = firstFragmentAttr
			fragment := Fragment{
				Attributes: attr,
			}

			n, err := reader.Read(s.Buffer)
			if n == 0 {
				if err != nil && err != io.EOF {
					if isArchiveContent {
						s.logger().Warn().Err(err).Str("path", fullPath).Msg("could not read archive content")
						if s.StrictArchives {
							return yield(fragment, fmt.Errorf("archive content %q: %w", fullPath, err))
						}
						return nil
					}
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}

			// Only check the filetype at the start of file.
			if prevFragmentEndLine == 0 && !s.ScanBinary {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
					if isArchiveContent {
						logging.Warn().Err(err).Str("path", fullPath).Msg("could not determine archive content type")
						return nil
					}
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", fullPath).
						Msgf("skipping binary file")

					return nil
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(s.Buffer[:n])
			stopAfterYield := false
			var boundaryErr error
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				if isArchiveContent {
					s.logger().Warn().Err(err).Str("path", fullPath).Msg("could not read archive content")
					stopAfterYield = true
					boundaryErr = err
				} else {
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
					)
				}
			}

			fragment.Raw = peekBuf.String()
			fragment.Bytes = peekBuf.Bytes()
			fragment.StartLine = prevFragmentEndLine + 1

			// Count the number of newlines in this chunk to determine the end
			// line for this fragment.
			prevFragmentEndLine += strings.Count(fragment.Raw, "\n")

			if s.Symlink != "" {
				symlink := s.Symlink
				if isWindows {
					symlink = filepath.ToSlash(s.Symlink)
				}
				fragment.SetAttr(AttrFSSymlink, symlink)
			}

			// log errors but continue since there's content
			if err != nil && err != io.EOF {
				if isArchiveContent {
					s.logger().Warn().Err(err).Str("path", fullPath).Msg("could not read archive content")
					if emitErr := yield(fragment, nil); emitErr != nil {
						return emitErr
					}
					return s.archiveFailure(yield, err)
				} else {
					logging.Warn().Err(err).Msgf("issue reading file")
				}
			}

			if stopAfterYield {
				if emitErr := yield(fragment, nil); emitErr != nil {
					return emitErr
				}
				return s.archiveFailure(yield, boundaryErr)
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			firstFragmentAttr = "false"
			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
}

// Copy source metadata so fragment-specific changes don't affect other fragments.
// Callers may override the resource type; the supplied path always takes precedence.
func (s *File) attributes(path string) map[string]string {
	attrs := make(map[string]string, len(s.Attributes)+2)
	attrs[AttrResource] = ResourceFileContent
	maps.Copy(attrs, s.Attributes)
	attrs[AttrPath] = path
	return attrs
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
