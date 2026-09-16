package sources

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources/internal/download"
)

// URL downloads and scans one HTTP(S) response, including supported archives.
// It does not crawl links. Authentication can be supplied through HTTPClient
// or URL userinfo. Userinfo and query parameters are omitted from attributes.
type URL struct {
	URL             string
	HTTPClient      *http.Client
	Logger          *slog.Logger
	ShouldSkip      SkipFunc
	MaxArchiveDepth int
	// MaxSize limits the downloaded response in bytes. Zero means unlimited.
	// Oversized responses are skipped before any fragments are emitted.
	MaxSize int64
}

func (s *URL) Fragments(ctx context.Context, yield FragmentsFunc) error {
	u, err := parseHTTPSource(s.URL)
	if err != nil {
		return err
	}
	if s.MaxSize < 0 {
		return errors.New("URL MaxSize must not be negative")
	}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		path = u.Hostname()
	}
	attrs := map[string]string{
		AttrPath:     path,
		AttrURL:      urlredact.Public(u),
		AttrResource: ResourceURLContent,
	}
	if s.ShouldSkip != nil && s.ShouldSkip(attrs) {
		return nil
	}
	return download.WithFile(ctx, download.Options{
		URL: s.URL, HTTPClient: s.HTTPClient, MaxSize: s.MaxSize, Logger: s.Logger,
	}, func(content *os.File) error {
		file := &File{
			Content: content, Path: path, Attributes: attrs,
			Logger: s.Logger, ShouldSkip: s.ShouldSkip,
			MaxArchiveDepth: s.MaxArchiveDepth, DetectArchive: true,
		}
		return file.Fragments(ctx, yield)
	})
}

func parseHTTPSource(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("source requires an absolute HTTP(S) URL")
	}
	return u, nil
}
