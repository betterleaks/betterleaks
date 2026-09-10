package sources

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"runtime"

	"github.com/mholt/archives"

	"github.com/betterleaks/betterleaks/v2/sources/internal/sourceutil"
)

const (
	maxPeekSize = 25 * 1_000 // 25kb
)

var isWhitespace [256]bool
var isWindows = runtime.GOOS == "windows"

func init() {
	// define whitespace characters
	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
}

// isArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func isArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// shouldSkipPath checks a path against the skip callback.
// Also handles the Windows forward-slash path normalization workaround.
func shouldSkipPath(skip SkipFunc, path string) bool {
	if skip == nil {
		return false
	}
	attrs := map[string]string{AttrPath: path}
	if sourceutil.ShouldSkipAttrs(skip, attrs) {
		return true
	}
	// TODO: Remove this Windows workaround in v9 (gitleaks/gitleaks#1641).
	if isWindows {
		attrs[AttrPath] = filepath.ToSlash(path)
		return sourceutil.ShouldSkipAttrs(skip, attrs)
	}
	return false
}

// readUntilSafeBoundary consumes r until it finds two consecutive `\n`
// characters, up to maxPeekSize bytes beyond initialSize. data must contain the
// initial read. Spare capacity is used for lookahead when available; otherwise
// the chunk grows once before any bytes are appended.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, data []byte, initialSize int, maxPeekSize int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)

	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return data, nil
				}
			} else if isWhitespace[lastChar] {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	if maxPeekSize > 0 && cap(data)-len(data) < maxPeekSize {
		grown := make([]byte, len(data), len(data)+maxPeekSize)
		copy(grown, data)
		data = grown
	}
	newlineCount = 0
	for {
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if isWhitespace[lastChar] {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (len(data) - initialSize) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return data, err
		}
		data = append(data, b)
	}
	return data, nil
}
