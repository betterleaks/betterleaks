package sources

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mholt/archives"
)

const (
	maxPeekSize     = 25 * 1_000 // 25kb
	downloadTimeout = 5 * time.Minute
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

// shouldSkipAttrs evaluates the skip callback against attrs.
// Returns true if the fragment should be skipped.
// If no callback is set (nil), nothing is skipped.
func shouldSkipAttrs(skip SkipFunc, attrs map[string]string) bool {
	if skip == nil {
		return false
	}
	return skip(attrs)
}

// shouldSkipPath checks a path against the skip callback.
// Also handles the Windows forward-slash path normalization workaround.
func shouldSkipPath(skip SkipFunc, path string) bool {
	if skip == nil {
		return false
	}
	attrs := map[string]string{AttrPath: path}
	if shouldSkipAttrs(skip, attrs) {
		return true
	}
	// TODO: Remove this Windows workaround in v9 (gitleaks/gitleaks#1641).
	if isWindows {
		attrs[AttrPath] = filepath.ToSlash(path)
		return shouldSkipAttrs(skip, attrs)
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

type sourceDownloadOptions struct {
	URL             string
	Reader          io.ReadCloser
	HTTPClient      *http.Client
	Path            string
	Attrs           map[string]string
	BearerToken     string
	MaxArchiveDepth int
	ShouldSkip      SkipFunc
	TempPattern     string
	Logger          *slog.Logger
}

// downloadAndScanSource downloads content from a URL or scans an existing reader via File.
func downloadAndScanSource(ctx context.Context, opts sourceDownloadOptions, yield FragmentsFunc) error {
	start := time.Now()
	reader := opts.Reader

	if reader == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
		if err != nil {
			return err
		}
		if opts.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+opts.BearerToken)
		}
		httpClient := opts.HTTPClient
		if httpClient == nil {
			httpClient = &http.Client{
				Timeout: downloadTimeout,
			}
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("download returned %s", resp.Status)
		}
		reader = resp.Body
	}
	defer reader.Close()

	tempPattern := opts.TempPattern
	if tempPattern == "" {
		tempPattern = "betterleaks-download-*"
	}
	tmp, err := os.CreateTemp("", tempPattern)
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if _, err := io.Copy(tmp, reader); err != nil {
		return fmt.Errorf("download %s: %w", opts.Path, err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	file := &File{
		Content:         tmp,
		Path:            opts.Path,
		MaxArchiveDepth: max(1, opts.MaxArchiveDepth),
		ShouldSkip:      opts.ShouldSkip,
		Logger:          opts.Logger,
	}
	err = file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range opts.Attrs {
				if k == AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
	loggerOrDiscard(opts.Logger).Debug("download scan complete", "path", opts.Path, "scan_duration", time.Since(start).Round(time.Millisecond))
	return err
}
