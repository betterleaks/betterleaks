package download

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/logging"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const downloadTimeout = 5 * time.Minute

type Options struct {
	URL             string
	Reader          io.ReadCloser
	HTTPClient      *http.Client
	Path            string
	Attrs           map[string]string
	BearerToken     string
	MaxArchiveDepth int
	ShouldSkip      sources.SkipFunc
	TempPattern     string
	Logger          *slog.Logger
}

// Scan downloads content from a URL or scans an existing reader via File.
func Scan(ctx context.Context, opts Options, yield sources.FragmentsFunc) error {
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

	file := &sources.File{
		Content:         tmp,
		Path:            opts.Path,
		MaxArchiveDepth: max(1, opts.MaxArchiveDepth),
		ShouldSkip:      opts.ShouldSkip,
		Logger:          opts.Logger,
	}
	err = file.Fragments(ctx, func(fragment sources.Fragment, err error) error {
		if err == nil {
			for k, v := range opts.Attrs {
				if k == sources.AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
	logging.OrDiscard(opts.Logger).Debug("download scan complete", "path", opts.Path, "scan_duration", time.Since(start).Round(time.Millisecond))
	return err
}
