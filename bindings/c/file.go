//go:build cgo && betterleaks_ffi

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/sources"
)

func (s *nativeScanner) scanFile(pathBytes, attributeJSON []byte) ([]byte, error) {
	if len(pathBytes) > maxPathBytes {
		return nil, failure(statusLimit, "file path exceeds 1 MiB")
	}
	if len(pathBytes) == 0 || !utf8.Valid(pathBytes) || bytes.IndexByte(pathBytes, 0) >= 0 {
		return nil, failure(statusInvalid, "file path must be non-empty UTF-8 without NUL bytes")
	}
	attributes, err := sourceAttributes(attributeJSON)
	if err != nil {
		return nil, err
	}
	path := string(pathBytes)
	// Reject special files before opening, and check the opened descriptor too.
	// The Unix opener also uses O_NONBLOCK so a concurrent replacement with a
	// FIFO cannot block open. Symlinks to regular files are followed.
	info, err := os.Stat(path)
	if err != nil {
		return nil, &apiError{statusScan, err}
	}
	if !info.Mode().IsRegular() {
		return nil, failure(statusInvalid, "scan_file requires a regular file")
	}
	file, err := openScanFile(path)
	if err != nil {
		return nil, &apiError{statusScan, err}
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, &apiError{statusScan, err}
	}
	if !info.Mode().IsRegular() {
		return nil, failure(statusInvalid, "scan_file requires a regular file")
	}
	if info.Size() > int64(s.maxInputBytes) {
		return nil, failure(statusLimit, "file exceeds max_input_bytes")
	}
	// Preserve the supplied relative/absolute path, normalizing Windows separators
	// just as the filesystem source does. Caller metadata cannot spoof the path.
	attributes[sources.AttrPath] = filepath.ToSlash(path)
	attributes[sources.AttrResource] = sources.ResourceFileContent
	reader := &fileTextReader{reader: file, remaining: s.maxInputBytes}
	result, err := s.scanSource(&nativeFileSource{
		reader: sources.Reader{Content: reader, Attributes: attributes}, prefilter: s.prefilter,
	})
	if err != nil {
		return nil, fmt.Errorf("scan file %q: %w", path, err)
	}
	return result, nil
}

// Add filesystem fragment metadata without opting into the filesystem source's
// archive expansion. In particular, path-only rules must run once per file.
type nativeFileSource struct {
	reader    sources.Reader
	prefilter sources.PrefilterFunc
}

func (s *nativeFileSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	first := "true"
	seen := false
	emit := func(fragment sources.Fragment, err error) error {
		seen = true
		if err != nil {
			return yield(fragment, err)
		}
		fragment.SetAttr(sources.AttrFSFirstFragment, first)
		first = "false"
		if s.prefilter != nil && s.prefilter(fragment.Attributes) {
			return nil
		}
		return yield(fragment, nil)
	}
	if err := s.reader.Fragments(ctx, emit); err != nil {
		return err
	}
	if !seen {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reader emits nothing for an empty file. Its path still participates in
		// path-only rules and filters, with the same metadata as a nonempty file.
		return emit(sources.Fragment{StartLine: 1, Attributes: maps.Clone(s.reader.Attributes)}, nil)
	}
	return nil
}

// Validate UTF-8 across arbitrary read boundaries and enforce the byte limit
// while reading, even if a file grows after Stat. Retain at most one incomplete
// rune. One extra byte distinguishes an exact-limit file from a truncated scan.
type fileTextReader struct {
	reader    io.Reader
	remaining int
	tail      [utf8.UTFMax]byte
	tailLen   int
}

func (r *fileTextReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	n, err := r.reader.Read(p)
	if n > r.remaining {
		return 0, failure(statusLimit, "file exceeds max_input_bytes")
	}
	r.remaining -= n
	data := p[:n]
	if r.tailLen > 0 {
		for len(data) > 0 && !utf8.FullRune(r.tail[:r.tailLen]) {
			r.tail[r.tailLen] = data[0]
			r.tailLen++
			data = data[1:]
		}
		if utf8.FullRune(r.tail[:r.tailLen]) {
			if !utf8.Valid(r.tail[:r.tailLen]) {
				return 0, failure(statusInvalid, "file content must be valid UTF-8")
			}
			r.tailLen = 0
		}
	}
	if !utf8.Valid(data) {
		// Valid text may end with an incomplete rune; all other invalid UTF-8
		// fails immediately. utf8.FullRune treats invalid encodings as complete.
		start := len(data) - 1
		for start > 0 && !utf8.RuneStart(data[start]) {
			start--
		}
		if utf8.FullRune(data[start:]) || !utf8.Valid(data[:start]) {
			return 0, failure(statusInvalid, "file content must be valid UTF-8")
		}
		r.tailLen = copy(r.tail[:], data[start:])
	}
	if err == io.EOF && r.tailLen != 0 {
		return 0, failure(statusInvalid, "file content must be valid UTF-8")
	}
	return n, err
}
