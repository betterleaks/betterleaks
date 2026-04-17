package sources

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"runtime"

	"github.com/betterleaks/betterleaks/celenv"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/mholt/archives"
)

const maxPeekSize = 25 * 1_000 // 10kb

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

// shouldSkipAttrs evaluates the global prefilter program against attrs.
// Returns true if the fragment should be skipped.
// If no prefilter program is compiled (nil), falls back to checking path against
// legacy Allowlists so callers work correctly without CEL compilation.
func shouldSkipAttrs(cfg *config.Config, attrs map[string]string) bool {
	if cfg == nil {
		return false
	}
	prg := cfg.PrefilterProgram()
	if prg != nil {
		skip, err := celenv.EvalPrefilter(prg, attrs)
		if err != nil {
			logging.Warn().Err(err).Msg("prefilter eval error; not skipping")
			return false
		}
		return skip
	}
	// Legacy fallback: check path only.
	path := attrs[AttrPath]
	if path == "" {
		return false
	}
	return false
}

// shouldSkipPath checks a path against the global prefilter or legacy allowlists.
// Also handles the Windows forward-slash path normalization workaround.
func shouldSkipPath(cfg *config.Config, path string) bool {
	if cfg == nil {
		logging.Trace().Str("path", path).Msg("not skipping path because config is nil")
		return false
	}
	attrs := map[string]string{AttrPath: path}
	if shouldSkipAttrs(cfg, attrs) {
		return true
	}
	// TODO: Remove this Windows workaround in v9 (gitleaks/gitleaks#1641).
	if isWindows {
		attrs[AttrPath] = filepath.ToSlash(path)
		return shouldSkipAttrs(cfg, attrs)
	}
	return false
}

// readUntilSafeBoundary consumes |f| until it finds two consecutive `\n` characters, up to |maxPeekSize|.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
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
					return nil
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
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
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
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}
