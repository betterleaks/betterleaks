package sources

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources/internal/targeturl"
)

// Kind identifies a source without constructing it. UnknownKind is returned on error.
type Kind uint8

const (
	UnknownKind Kind = iota
	FilesystemKind
	GitKind
	URLKind
	GitHubKind
	GitLabKind
	HuggingFaceKind
	S3Kind
)

// String returns the source's command name, or "unknown" for an unknown kind.
func (k Kind) String() string {
	names := [...]string{"unknown", "filesystem", "git", "url", "github", "gitlab", "huggingface", "s3"}
	if int(k) >= len(names) {
		return "unknown"
	}
	return names[k]
}

type autoOptions struct {
	client http.Client
	logger *slog.Logger
}

// AutoOption configures Auto.
type AutoOption func(*autoOptions)

// WithAutoHTTPClient supplies the client used for Git discovery, including any
// authentication transport. Detection still limits request time and redirects.
func WithAutoHTTPClient(client *http.Client) AutoOption {
	return func(opts *autoOptions) {
		if client != nil {
			opts.client = *client
		}
	}
}

// WithAutoLogger receives source selection and Git discovery diagnostics.
// A nil logger disables logging.
func WithAutoLogger(logger *slog.Logger) AutoOption {
	return func(opts *autoOptions) { opts.logger = logger }
}

// Auto identifies an existing local path or a supported absolute URL.
// Local paths, including Git checkouts, always select filesystem scanning.
// Ambiguous HTTP(S) URLs make a bounded Git smart HTTP discovery request.
// Authentication is supplied through WithAutoHTTPClient; environment variables
// are never read. Callers can bypass discovery by constructing a source directly.
func Auto(ctx context.Context, target string, opts ...AutoOption) (kind Kind, err error) {
	var options autoOptions
	for _, opt := range opts {
		opt(&options)
	}
	logger := logging.OrDiscard(options.logger)
	defer func() {
		if err == nil {
			loggedTarget := target
			if u, parseErr := url.Parse(target); parseErr == nil && u.Scheme != "" && u.Host != "" {
				loggedTarget = urlredact.Public(u)
			}
			logger.InfoContext(ctx, "auto: selected source", "source", kind.String(), "target", loggedTarget)
		}
	}()
	if err := ctx.Err(); err != nil {
		return UnknownKind, err
	}
	_, statErr := os.Stat(target)
	if statErr == nil {
		return FilesystemKind, nil
	}
	u, err := url.Parse(target)
	if os.IsPermission(statErr) || (err == nil && u.Scheme == "" && !os.IsNotExist(statErr)) {
		return UnknownKind, statErr
	}
	if err != nil || u.Scheme == "" || u.Host == "" {
		return UnknownKind, errors.New("source must be an existing local path or an absolute URL with a supported scheme")
	}
	switch u.Scheme {
	case "s3":
		return S3Kind, nil
	case "hf":
		if _, err := targeturl.ParseHuggingFace(target); err == nil {
			return HuggingFaceKind, nil
		}
		return UnknownKind, errors.New("supported hf URLs use hf://buckets/owner/bucket[/prefix]")
	case "http", "https":
	default:
		return UnknownKind, fmt.Errorf("unsupported source scheme %q; use a local path or HTTP(S), s3, or hf URL", u.Scheme)
	}

	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	if strings.HasSuffix(host, ".r2.cloudflarestorage.com") ||
		(strings.HasSuffix(host, ".amazonaws.com") &&
			(strings.HasPrefix(host, "s3.") || strings.HasPrefix(host, "s3-") || strings.Contains(host, ".s3.") || strings.Contains(host, ".s3-"))) {
		return S3Kind, nil
	}
	// Provider parsers own the URL grammar; detection only chooses the scan mode.
	gitlabNamespace := false
	switch host {
	case "github.com", "gist.github.com":
		if parsed, err := targeturl.ParseGitHub(target); err == nil {
			if parsed.Resource == "repo" {
				return GitKind, nil
			}
			return GitHubKind, nil
		}
	case "gitlab.com":
		if parsed, err := targeturl.ParseGitLab(target); err == nil && parsed.Path != "" {
			if parsed.Kind != "namespace" || !strings.Contains(parsed.Path, "/") {
				return GitLabKind, nil
			}
			gitlabNamespace = true
		}
	case "huggingface.co":
		if parsed, err := targeturl.ParseHuggingFace(target); err == nil {
			if parsed.Kind == "repo" {
				return GitKind, nil
			}
			return HuggingFaceKind, nil
		}
	}
	if strings.HasSuffix(path, ".git") {
		return GitKind, nil
	}
	logger.DebugContext(ctx, "auto: checking URL for a Git repository", "target", urlredact.Public(u))
	git, err := probeGit(ctx, u, &options.client)
	if err != nil {
		return UnknownKind, fmt.Errorf("could not determine source type: %w; select git or url explicitly", err)
	}
	if git {
		return GitKind, nil
	}
	if gitlabNamespace {
		return GitLabKind, nil
	}
	return URLKind, nil
}

func probeGit(ctx context.Context, target *url.URL, client *http.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u := *target
	u.RawPath = strings.TrimRight(u.EscapedPath(), "/") + "/info/refs"
	u.Path, _ = url.PathUnescape(u.RawPath)
	u.Fragment = ""
	query := u.Query()
	query.Set("service", "git-upload-pack")
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, urlredact.Error(err)
	}
	req.Header.Set("Git-Protocol", "version=2")
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("Git discovery exceeded three redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return errors.New("Git discovery redirected to an unsupported scheme")
		}
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
			req.Header.Del("Authorization")
		}
		if checkRedirect != nil {
			return checkRedirect(req, via)
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, urlredact.Error(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Git discovery returned HTTP %d", resp.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType != "application/x-git-upload-pack-advertisement" {
		return false, nil
	}
	if err := readGitAdvertisement(io.LimitReader(resp.Body, 64<<10)); err != nil {
		return false, fmt.Errorf("invalid Git advertisement: %w", err)
	}
	return true, nil
}

// Inspect the advertisement, not the whole ref list: large repositories can
// advertise megabytes of refs. v2 starts with a version line, while v0/v1
// advertisements start with the service announcement and a flush packet.
func readGitAdvertisement(r io.Reader) error {
	reader := bufio.NewReader(r)
	packet := func() (string, error) {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return "", err
		}
		n, err := strconv.ParseUint(string(header[:]), 16, 16)
		if err != nil || (n != 0 && n < 4) || n > 65520 {
			return "", errors.New("invalid packet length")
		}
		if n == 0 {
			return "", nil
		}
		body := make([]byte, n-4)
		_, err = io.ReadFull(reader, body)
		return string(body), err
	}
	line, err := packet()
	if err != nil {
		return err
	}
	if line == "# service=git-upload-pack\n" {
		flush, err := packet()
		if err != nil {
			return err
		}
		if flush != "" {
			return errors.New("missing service flush")
		}
		line, err = packet()
		if err != nil {
			return err
		}
	}
	if line == "version 2\n" {
		// Require the ls-refs capability before accepting a v2 server.
		for {
			line, err = packet()
			if err != nil {
				return err
			}
			if strings.TrimSpace(line) == "ls-refs" || strings.HasPrefix(line, "ls-refs=") {
				return nil
			}
			if line == "" {
				return errors.New("missing ls-refs capability")
			}
		}
	}
	if line == "version 1\n" {
		line, err = packet()
		if err != nil {
			return err
		}
	}
	oid, ref, ok := strings.Cut(line, " ")
	if ok && (len(oid) == 40 || len(oid) == 64) {
		if strings.Trim(oid, "0123456789abcdef") == "" &&
			(strings.HasPrefix(ref, "refs/") || strings.HasPrefix(ref, "HEAD\x00") || strings.HasPrefix(ref, "capabilities^{}\x00")) {
			return nil
		}
	}
	return errors.New("missing version or ref advertisement")
}
