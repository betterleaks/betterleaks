package filesystem

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"

	"github.com/andybalholm/brotli"
	"github.com/betterleaks/betterleaks/v2/sources/internal/stream"
	"github.com/mholt/archives"
)

// Each filesystem worker owns its probe. A short regular file fits entirely
// in the buffer and can be scanned without a second read from disk.
type diskArchiveProbe struct {
	header  [stream.BufferSize]byte
	content bytes.Reader
	input   bytes.Reader
	decoder brotli.Reader
	output  [1024]byte
}

// The CLI reads ahead by one scanner chunk. For a plain file, the scanner
// continues from the same buffered input without rereading or seeking.
func (p *diskArchiveProbe) identify(ctx context.Context, f *os.File) (archives.Format, io.Reader, error) {
	n, err := io.ReadAtLeast(f, p.header[:], len(p.output))
	header := p.header[:n]
	p.content.Reset(header)
	var content io.Reader = &p.content
	switch err {
	case nil:
		content = io.MultiReader(&p.content, f)
	case io.EOF, io.ErrUnexpectedEOF: // The complete file is already buffered.
	default:
		// The permissive filename fallback may still scan the original file.
		_, seekErr := f.Seek(0, io.SeekStart)
		return nil, f, errors.Join(err, seekErr)
	}
	// Tar may read extended headers past the first buffer.
	full := io.NewSectionReader(cachedHeader{f, header}, 0, math.MaxInt64)
	if !p.possibleArchive(ctx, header, full) {
		return nil, content, archives.NoMatch
	}
	if _, err := full.Seek(0, io.SeekStart); err != nil {
		return nil, content, err
	}
	format, _, err := archives.Identify(ctx, "", full)
	return format, content, err
}

// Matchers read and rewind the same header repeatedly. Buffer disk reads,
// allowing matchers such as PAX tar to read past the prefix when necessary.
func identifyContent(ctx context.Context, content io.Reader, worker *diskArchiveProbe) (archives.Format, io.Reader, error) {
	f, ok := content.(*os.File)
	if !ok {
		return archives.Identify(ctx, "", content)
	}
	if worker != nil {
		return worker.identify(ctx, f)
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		// An os.File can also be a pipe, which only supports sequential reads.
		return archives.Identify(ctx, "", struct{ io.Reader }{f})
	}
	file := io.NewSectionReader(f, offset, math.MaxInt64-offset)
	var header [1024]byte
	n, err := file.ReadAt(header[:], 0)
	var probe io.Reader = bytes.NewReader(header[:n])
	if err == nil {
		probe = io.NewSectionReader(cachedHeader{file, header[:]}, 0, file.Size())
	} else if err != io.EOF {
		return nil, f, err
	}
	format, _, err := archives.Identify(ctx, "", probe)
	return format, f, err
}

type cachedHeader struct {
	io.ReaderAt
	header []byte
}

func (r cachedHeader) ReadAt(p []byte, off int64) (int, error) {
	if off >= 0 && off <= int64(len(r.header)-len(p)) {
		return copy(p, r.header[off:]), nil
	}
	return r.ReaderAt.ReadAt(p, off)
}

// These built-in matchers only inspect a fixed-size prefix. Let the archive
// library interpret their signatures (including ZIP variants and zlib flags).
var headerFormats = [...]archives.Format{
	archives.Zip{}, archives.Gz{}, archives.Zstd{}, archives.Bz2{}, archives.Xz{},
	archives.Rar{}, archives.SevenZip{}, archives.Lz4{}, archives.Lzip{},
	archives.MinLZ{}, archives.Sz{}, archives.Zlib{},
}

func (p *diskArchiveProbe) possibleArchive(ctx context.Context, h []byte, full io.Reader) bool {
	for _, format := range headerFormats {
		p.input.Reset(h)
		match, err := format.Match(ctx, "", &p.input)
		if err != nil || match.ByStream {
			return true
		}
	}
	if len(h) >= 512 {
		match, err := (archives.Tar{}).Match(ctx, "", full)
		if err != nil || match.ByStream {
			return true
		}
	}

	// Brotli has no magic bytes. Try decoding the same 1 KiB sample as
	// archives.Brotli.Match with worker-owned buffers. A successful decode
	// still goes through Identify to resolve ambiguous or compound formats.
	h = h[:min(len(h), len(p.output))]
	p.input.Reset(h)
	_ = p.decoder.Reset(&p.input)
	for total := 0; total < len(p.output); {
		n, err := p.decoder.Read(p.output[:len(h)])
		if err != nil {
			return err == io.EOF
		}
		if n == 0 {
			return true
		}
		total += n
	}
	return true
}
