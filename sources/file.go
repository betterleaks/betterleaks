package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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
		// fileFragments may read up to maxPeekSize beyond the normal chunk while
		// looking for a safe boundary. Reserve that space once so bytes.Buffer
		// does not have to grow and copy every full-sized chunk.
		buf := make([]byte, defaultBufferSize, defaultBufferSize+maxPeekSize)
		return &buf
	},
}

func getBuffer() *[]byte {
	buffer := bufferPool.Get().(*[]byte)
	*buffer = (*buffer)[:defaultBufferSize]
	return buffer
}

func putBuffer(buffer *[]byte) {
	if buffer == nil {
		return
	}
	// Keep the read size stable even though pooled buffers have spare capacity
	// for readUntilSafeBoundary.
	*buffer = (*buffer)[:defaultBufferSize]
	bufferPool.Put(buffer)
}

var readerPool = sync.Pool{
	New: func() any {
		// Reader capacity affects fragment boundaries when an archive reader
		// returns short reads. Keep bufio's historical default capacity so this
		// refactor does not change finding locations or component grouping. The
		// batched safe-boundary scan still avoids the old ReadByte loop.
		return bufio.NewReader(nil)
	},
}

var ephemeralFragmentAttributesPool = sync.Pool{
	New: func() any {
		return make(map[string]string, 3)
	},
}

var fileFragmentPool = sync.Pool{
	New: func() any { return new(Fragment) },
}

func newFileFragment(path string) *Fragment {
	fragment := fileFragmentPool.Get().(*Fragment)
	attrs := ephemeralFragmentAttributesPool.Get().(map[string]string)
	attrs[AttrPath] = path
	attrs[AttrResource] = ResourceFileContent
	fragment.Attributes = attrs
	fragment.attributesLease = attrs
	fragment.release = releaseFileFragment
	fragment.owner = fragment
	return fragment
}

func releaseFileFragment(fragment *Fragment) {
	if fragment == nil {
		return
	}
	bufferLease := fragment.bufferLease
	attrs := fragment.attributesLease
	*fragment = Fragment{}
	if bufferLease != nil {
		putBuffer(bufferLease)
	}
	if attrs != nil {
		clear(attrs)
		ephemeralFragmentAttributesPool.Put(attrs)
	}
	fileFragmentPool.Put(fragment)
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

// fragmentCallbackPanic distinguishes a caller panic from a panic raised by an
// archive implementation. Archive panics are treated as malformed input, but
// swallowing a caller panic would violate the Fragments callback contract and
// can hide programmer errors.
type fragmentCallbackPanic struct {
	value any
}

func preserveFragmentCallbackPanic(yield FragmentsFunc) FragmentsFunc {
	return func(fragment *Fragment, err error) error {
		defer func() {
			if recovered := recover(); recovered != nil {
				panic(&fragmentCallbackPanic{value: recovered})
			}
		}()
		return yield(fragment, err)
	}
}

func recoverArchivePanic(path, operation string, returnErr *error) {
	if recovered := recover(); recovered != nil {
		if callbackPanic, ok := recovered.(*fragmentCallbackPanic); ok {
			panic(callbackPanic.value)
		}
		logging.Warn().
			Str("path", path).
			Str("panic", fmt.Sprint(recovered)).
			Msg("skipping archive: panic during " + operation)
		*returnErr = nil
	}
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
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
	if s == nil {
		return fmt.Errorf("sources: file source is required")
	}
	if s.Content == nil {
		return fmt.Errorf("sources: file content is required")
	}
	if yield == nil {
		return fmt.Errorf("sources: file fragment callback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.fragments(ctx, yield)
}

func (s *File) fragments(ctx context.Context, yield FragmentsFunc) error {
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
			var event *zerolog.Event

			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				event = logging.Warn()
			} else {
				event = logging.Trace()
			}

			event.Str(
				"path", s.FullPath(),
			).Int(
				"max_archive_depth", s.MaxArchiveDepth,
			).Msg("skipping archive: exceeds max archive depth")

			return nil
		}
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, stream, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(ctx, decompressor, stream, yield)
		}
		logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	}

	br := getReader(stream)
	defer putReader(br)
	isArchiveContent := s.archiveDepth > 0
	return s.fileFragments(ctx, br, isArchiveContent, yield)
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) (returnErr error) { //nolint:nonamedreturns // panic recovery must set the returned error
	// Malformed archives can make the extraction library panic (e.g. a tiny
	// .rar whose block header encodes a bogus size). Recover here so a bad
	// archive is skipped with a warning instead of killing the process. This
	// guard sits inside extractorFragments (rather than at the dispatch site)
	// so it protects every nesting level: extractorFragments recurses into
	// nested entries via file.Fragments below.
	defer recoverArchivePanic(s.FullPath(), "extraction", &returnErr)
	yield = preserveFragmentCallbackPanic(yield)

	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "betterleaks-archive-")
			if err != nil {
				return fmt.Errorf("create archive temporary file: %w", err)
			}
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				return fmt.Errorf("copy archive to temporary file: %w", err)
			}

			reader = tmpfile
		}
	}

	var (
		callbackErr     error
		callbackErrOnce sync.Once
	)
	trackedYield := func(fragment *Fragment, err error) error {
		yieldErr := yield(fragment, err)
		if yieldErr != nil {
			callbackErrOnce.Do(func() { callbackErr = yieldErr })
		}
		return yieldErr
	}
	err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		path := filepath.Clean(d.NameInArchive)
		if !d.Mode().IsRegular() {
			logging.Trace().Str("path", path).Msg("skipping non-regular file")
			return nil
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Warn().Err(err).Str("path", s.FullPath()).Msg("could not open archive inner file")
			return nil
		}
		defer innerReader.Close()

		if s.ShouldSkip != nil && shouldSkipPath(s.ShouldSkip, path) {
			logging.Debug().Str("path", s.FullPath()).Msg("skipping file: global allowlist")
			return nil
		}

		file := &File{
			Content:         innerReader,
			Path:            path,
			Symlink:         s.Symlink,
			ShouldSkip:      s.ShouldSkip,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
		}

		return file.fragments(ctx, trackedYield)
	})

	if callbackErr != nil {
		return callbackErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		logging.Warn().Err(err).Str("path", s.FullPath()).Msg("error reading archive")
	}
	return nil
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) (returnErr error) { //nolint:nonamedreturns // panic recovery must set the returned error
	// Register recovery before cleanup so it runs last and can also catch a
	// panic from closing a malformed decompressor reader.
	defer recoverArchivePanic(s.FullPath(), "decompression", &returnErr)
	yield = preserveFragmentCallbackPanic(yield)

	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Warn().Err(err).Str("path", s.FullPath()).Msg("could not read compressed file")
		return nil
	}
	defer func() {
		_ = innerReader.Close()
	}()

	br := getReader(innerReader)
	defer putReader(br)
	return s.fileFragments(ctx, br, true, yield)
}

// fileFragments reads the file into fragments to yield.
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, isArchiveContent bool, yield FragmentsFunc) error {
	prevFragmentEndLine := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			bufferLease := getBuffer()
			buffer := *bufferLease
			n, err := reader.Read(buffer)
			if n == 0 {
				putBuffer(bufferLease)
				if err != nil && err != io.EOF {
					fullPath := s.FullPath()
					if isArchiveContent {
						logging.Warn().Err(err).Str("path", fullPath).Msg("could not read archive content")
						return nil
					}
					fragPath := fullPath
					if isWindows {
						fragPath = filepath.ToSlash(fullPath)
					}
					fragment := newFileFragment(fragPath)
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}
			// Build fragment metadata only after reading content. Every file has a
			// final zero-byte EOF probe, which should not allocate an unused map.
			fullPath := s.FullPath()
			fragPath := fullPath
			if isWindows {
				fragPath = filepath.ToSlash(fullPath)
			}
			// Only check the filetype at the start of file.
			if prevFragmentEndLine == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(buffer[:n]); err != nil {
					putBuffer(bufferLease)
					if isArchiveContent {
						logging.Warn().Err(err).Str("path", fullPath).Msg("could not determine archive content type")
						return nil
					}
					return yield(
						newFileFragment(fragPath),
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					putBuffer(bufferLease)
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", fullPath).
						Msgf("skipping binary file")

					return nil
				}
			}
			fragment := newFileFragment(fragPath)

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(buffer[:n])
			stopAfterYield := false
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				if isArchiveContent {
					logging.Warn().Err(err).Str("path", fullPath).Msg("could not read archive content until safe boundary")
					stopAfterYield = true
				} else {
					fragment.Raw = peekBuf.Bytes()
					fragment.bufferLease = bufferLease
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
					)
				}
			}

			fragment.Raw = peekBuf.Bytes()
			fragment.bufferLease = bufferLease
			fragment.StartLine = prevFragmentEndLine + 1

			// Count the number of newlines in this chunk to determine the end
			// line for this fragment.
			prevFragmentEndLine += bytes.Count(fragment.Raw, []byte{'\n'})

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
					logging.Warn().Err(err).Str("path", fullPath).Msg("issue reading archive content")
					return yield(fragment, nil)
				} else {
					logging.Warn().Err(err).Msgf("issue reading file")
				}
			}

			if stopAfterYield {
				return yield(fragment, nil)
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
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
