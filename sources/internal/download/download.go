// Package download owns HTTP fetching and temporary download files.
package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/logging"
)

type Options struct {
	URL string
	// Reader bypasses HTTP fetching. WithFile takes ownership and closes it.
	Reader      io.ReadCloser
	HTTPClient  *http.Client
	BearerToken string
	// MaxSize limits the response in bytes. Zero means unlimited.
	MaxSize     int64
	TempPattern string
	Logger      *slog.Logger
}

// WithFile downloads content, calls scan with a rewound file, and removes the
// file on every return path. Oversized responses are skipped without calling scan.
func WithFile(ctx context.Context, opts Options, scan func(*os.File) error) (err error) {
	defer func() { err = urlredact.Error(err) }()
	reader := opts.Reader
	if reader != nil {
		defer reader.Close()
	}
	if opts.MaxSize < 0 {
		return errors.New("download MaxSize must not be negative")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	contentLength := int64(-1)
	if reader == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
		if err != nil {
			return err
		}
		if opts.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+opts.BearerToken)
		}
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 5 * time.Minute}
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
		}
		reader, contentLength = resp.Body, resp.ContentLength
	}
	skipLarge := func() error {
		logging.OrDiscard(opts.Logger).WarnContext(ctx, "skipping download: exceeds maximum size", "url", urlredact.PublicString(opts.URL), "max_size", opts.MaxSize)
		return nil
	}
	if opts.MaxSize > 0 && contentLength > opts.MaxSize {
		return skipLarge()
	}
	pattern := opts.TempPattern
	if pattern == "" {
		pattern = "betterleaks-download-*"
	}
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	var body io.Reader = reader
	if opts.MaxSize > 0 {
		body = io.LimitReader(body, opts.MaxSize)
	}
	if _, err := io.Copy(tmp, body); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if opts.MaxSize > 0 {
		var extra [1]byte
		n, err := io.ReadFull(reader, extra[:])
		if n > 0 {
			return skipLarge()
		}
		if err != nil && err != io.EOF {
			return fmt.Errorf("download: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return scan(tmp)
}
