package huggingface

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/v2/internal/httpclient"
	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/internal/download"
	"github.com/betterleaks/betterleaks/v2/sources/internal/targeturl"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

const (
	huggingFaceDefaultBase                      = "https://huggingface.co/"
	huggingFacePerPage                          = 100
	huggingFaceAPIConcurrency                   = 10
	huggingFaceSnippetLimit                     = 200
	huggingFaceLargeObjectWarnThreshold   int64 = 1024 * 1024 * 1024
	huggingFaceDefaultMaxBucketObjectSize int64 = 250 * 1024 * 1024
)

// Source enumerates Hugging Face model, dataset, and Space repositories
// via the Hub API and delegates git history scanning to the sources.Git source.
type Source struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger *slog.Logger
	Token  string
	URL    string

	Include      []string
	Exclude      []string
	ExcludeRepos []string // glob patterns matched against "owner/name"
	Resources    ResourceSet

	Prefilter       sources.PrefilterFunc
	MaxArchiveDepth int
	LogOpts         string

	MaxBucketObjectSize int64

	httpClient *http.Client
	restRetry  *httpclient.RetryTransport
	baseURL    *url.URL
	apiSem     chan struct{}
}

type ResourceType string

const (
	ResourceTypeRepos       ResourceType = "repos"
	ResourceTypeDiscussions ResourceType = "discussions"
	ResourceTypePRs         ResourceType = "prs"
	ResourceTypeBuckets     ResourceType = "buckets"
)

var AllResourceTypes = []ResourceType{
	ResourceTypeRepos,
	ResourceTypeDiscussions,
	ResourceTypePRs,
	ResourceTypeBuckets,
}

type ResourceSet map[ResourceType]bool

func (rs ResourceSet) Has(r ResourceType) bool { return rs[r] }

func (rs ResourceSet) String() string {
	var out []string
	for rt := range rs {
		out = append(out, string(rt))
	}
	return strings.Join(out, ",")
}

// resolveResources checks the Hugging Face source configuration and resolves default
// resource selection.
func (s *Source) resolveResources() error {
	if s.URL == "" {
		return errors.New("target URL is required")
	}
	if _, err := ParseURL(s.URL); err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if len(s.Resources) == 0 {
		valid := make(map[ResourceType]bool, len(AllResourceTypes))
		for _, rt := range AllResourceTypes {
			valid[rt] = true
		}
		target, err := ParseURL(s.URL)
		if err != nil {
			return fmt.Errorf("invalid target URL: %w", err)
		}
		rs := ResourceSet{ResourceTypeRepos: true}
		if target.Kind == "bucket" {
			rs = ResourceSet{ResourceTypeBuckets: true}
		}
		for _, name := range s.Include {
			rt := ResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			rs[rt] = true
		}
		for _, name := range s.Exclude {
			rt := ResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			delete(rs, rt)
		}
		s.Resources = rs
	}
	return nil
}

func (s *Source) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := s.resolveResources(); err != nil {
		return err
	}
	if err := s.ensureClient(); err != nil {
		return err
	}
	logging.OrDiscard(s.Logger).Info("starting Hugging Face scan", "target", urlredact.PublicString(s.URL), "resources", s.Resources)
	start := time.Now()
	target, err := ParseURL(s.URL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	ctx, cancelScans := context.WithCancelCause(ctx)
	defer cancelScans(nil)
	// A rejected yield must stop enumeration even when resource errors are skippable.
	onFragment := yield
	yield = func(fragment sources.Fragment, err error) error {
		err = onFragment(fragment, err)
		if err != nil {
			cancelScans(err)
		}
		return err
	}
	var scanErr error
	wantsRepoScan := target.Kind != "bucket" &&
		(s.Resources.Has(ResourceTypeRepos) ||
			s.Resources.Has(ResourceTypeDiscussions) ||
			s.Resources.Has(ResourceTypePRs))
	if wantsRepoScan {
		repoCh, enumErrCh := s.enumerateRepos(ctx, target)
		var scans errgroup.Group
		repoCount := 0
		scans.Go(func() error {
			var firstErr error
			for repo := range repoCh {
				if err := context.Cause(ctx); err != nil {
					return err
				}
				repoCount++
				if err := s.scanRepo(ctx, repo, yield); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			return firstErr
		})
		if err := <-enumErrCh; err != nil {
			cancelScans(fmt.Errorf("enumerate Hugging Face repos: %w", err))
		}
		if err := scans.Wait(); err != nil && scanErr == nil {
			scanErr = err
		}
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		logging.OrDiscard(s.Logger).Info("scan complete", "repos", repoCount, "duration", time.Since(start))
	}
	if s.Resources.Has(ResourceTypeBuckets) {
		bucketCh, enumErrCh := s.enumerateBuckets(ctx, target)
		var scans errgroup.Group
		bucketCount := 0
		scans.Go(func() error {
			var firstErr error
			for bucket := range bucketCh {
				if err := context.Cause(ctx); err != nil {
					return err
				}
				bucketCount++
				if err := s.scanBucket(ctx, bucket, yield); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			return firstErr
		})
		if err := <-enumErrCh; err != nil {
			cancelScans(fmt.Errorf("enumerate Hugging Face buckets: %w", err))
		}
		if err := scans.Wait(); err != nil && scanErr == nil {
			scanErr = err
		}
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		logging.OrDiscard(s.Logger).Info("scan complete", "buckets", bucketCount, "duration", time.Since(start))
	}
	return scanErr
}

type RepoKind string

const (
	RepoKindModel   RepoKind = "model"
	RepoKindDataset RepoKind = "dataset"
	RepoKindSpace   RepoKind = "space"
)

type ParsedURL struct {
	Scheme string
	Host   string
	Kind   string // "owner" or "repo"
	Owner  string
	Name   string
	Type   RepoKind
	Prefix string
}

// ParseURL parses a Hugging Face owner, repository, or bucket URL.
func ParseURL(rawURL string) (*ParsedURL, error) {
	parsed, err := targeturl.ParseHuggingFace(rawURL)
	if err != nil {
		return nil, err
	}
	return &ParsedURL{
		Scheme: parsed.Scheme, Host: parsed.Host, Kind: parsed.Kind,
		Owner: parsed.Owner, Name: parsed.Name, Type: RepoKind(parsed.Type), Prefix: parsed.Prefix,
	}, nil
}

func cleanPathSegments(path string) []string { return targeturl.PathSegments(path) }

type huggingFaceRepo struct {
	Kind       RepoKind
	Owner      string
	Name       string
	Visibility string
}

func (r huggingFaceRepo) Slug() string { return r.Owner + "/" + r.Name }

func (r huggingFaceRepo) CanonicalKey() string {
	return string(r.Kind) + ":" + strings.ToLower(r.Slug())
}

func (r huggingFaceRepo) WebURL(base *url.URL) string {
	u := *base
	switch r.Kind {
	case RepoKindDataset:
		u.Path = strings.TrimSuffix(u.Path, "/") + "/datasets/" + r.Slug()
	case RepoKindSpace:
		u.Path = strings.TrimSuffix(u.Path, "/") + "/spaces/" + r.Slug()
	default:
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(r.Slug(), "/")
	}
	u.RawQuery = ""
	return u.String()
}

func (r huggingFaceRepo) GitURL(base *url.URL) string {
	return strings.TrimSuffix(r.WebURL(base), "/") + ".git"
}

func (s *Source) enumerateRepos(ctx context.Context, target *ParsedURL) (<-chan huggingFaceRepo, <-chan error) {
	ch := make(chan huggingFaceRepo, 1)
	errCh := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errCh)
		seen := make(map[string]bool)
		send := func(repo huggingFaceRepo) error {
			if repo.Owner == "" || repo.Name == "" {
				return nil
			}
			key := repo.CanonicalKey()
			if seen[key] {
				return nil
			}
			if s.isExcluded(repo.Slug()) {
				logging.OrDiscard(s.Logger).Debug("excluding Hugging Face repo", "repo", repo.Slug(), "type", string(repo.Kind))
				return nil
			}
			seen[key] = true
			select {
			case ch <- repo:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if target.Kind == "repo" {
			errCh <- send(huggingFaceRepo{Kind: target.Type, Owner: target.Owner, Name: target.Name})
			return
		}

		for _, kind := range []RepoKind{RepoKindModel, RepoKindDataset, RepoKindSpace} {
			logging.OrDiscard(s.Logger).Info("enumerating Hugging Face repositories", "owner", target.Owner, "type", string(kind))
			if err := s.streamReposByAuthor(ctx, kind, target.Owner, send); err != nil {
				errCh <- fmt.Errorf("list %s repos for %s: %w", kind, target.Owner, err)
				return
			}
		}
		errCh <- nil
	}()
	return ch, errCh
}

type huggingFaceBucket struct {
	Owner      string
	Name       string
	Prefix     string
	Private    bool
	Size       int64
	TotalFiles int64
}

func (b huggingFaceBucket) ID() string { return b.Owner + "/" + b.Name }

func (b huggingFaceBucket) WebURL(base *url.URL) string {
	u := *base
	pathValue := "buckets/" + b.ID()
	if b.Prefix != "" {
		pathValue += "/" + strings.TrimPrefix(b.Prefix, "/")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + pathValue
	u.RawQuery = ""
	return u.String()
}

func (s *Source) enumerateBuckets(ctx context.Context, target *ParsedURL) (<-chan huggingFaceBucket, <-chan error) {
	ch := make(chan huggingFaceBucket, 1)
	errCh := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errCh)
		send := func(bucket huggingFaceBucket) error {
			if s.isExcluded(bucket.ID()) {
				logging.OrDiscard(s.Logger).Debug("excluding Hugging Face bucket", "bucket", bucket.ID())
				return nil
			}
			logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "queueing Hugging Face bucket scan", "bucket", bucket.ID(), "prefix", bucket.Prefix)
			select {
			case ch <- bucket:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if target.Kind == "bucket" {
			errCh <- send(huggingFaceBucket{Owner: target.Owner, Name: target.Name, Prefix: target.Prefix})
			return
		}
		if target.Kind != "owner" {
			errCh <- nil
			return
		}
		logging.OrDiscard(s.Logger).Info("enumerating Hugging Face buckets", "owner", target.Owner)
		err := s.streamBuckets(ctx, target.Owner, send)
		if err != nil {
			err = fmt.Errorf("list buckets for %s: %w", target.Owner, err)
		}
		errCh <- err
	}()
	return ch, errCh
}

type huggingFaceBucketInfo struct {
	ID         string `json:"id"`
	Private    bool   `json:"private"`
	Size       int64  `json:"size"`
	TotalFiles int64  `json:"total_files"`
}

func (s *Source) streamBuckets(ctx context.Context, namespace string, yield func(huggingFaceBucket) error) error {
	if namespace == "" {
		namespace = "me"
	}
	u, err := s.apiURL("buckets/" + escapePathSegments(namespace))
	if err != nil {
		return err
	}
	return s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceBucketInfo
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode buckets: %w; body snippet: %s", err, snippet(body))
		}
		for _, item := range page {
			owner, name, ok := splitOwnerName(item.ID)
			if !ok {
				logging.OrDiscard(s.Logger).Warn("skipping Hugging Face bucket with unexpected identifier", "bucket", item.ID)
				continue
			}
			if err := yield(huggingFaceBucket{
				Owner:      owner,
				Name:       name,
				Private:    item.Private,
				Size:       item.Size,
				TotalFiles: item.TotalFiles,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func splitOwnerName(id string) (owner, name string, ok bool) {
	owner, name, ok = strings.Cut(strings.Trim(id, "/"), "/")
	return owner, name, ok && owner != "" && name != ""
}

type huggingFaceListItem struct {
	ID         string `json:"id"`
	ModelID    string `json:"modelId"`
	Private    bool   `json:"private"`
	IsPrivate  bool   `json:"isPrivate"`
	Visibility string `json:"visibility"`
}

func (i huggingFaceListItem) identifier() string {
	if i.ID != "" {
		return i.ID
	}
	return i.ModelID
}

func (i huggingFaceListItem) visibility() string {
	if i.Visibility != "" {
		return i.Visibility
	}
	if i.Private || i.IsPrivate {
		return "private"
	}
	return ""
}

func (s *Source) streamReposByAuthor(ctx context.Context, kind RepoKind, author string, yield func(huggingFaceRepo) error) error {
	u, err := s.apiURL(kind.apiPath())
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("author", author)
	q.Set("limit", strconv.Itoa(huggingFacePerPage))
	u.RawQuery = q.Encode()

	return s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceListItem
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode %s list: %w; body snippet: %s", kind, err, snippet(body))
		}
		for idx, item := range page {
			owner, name, ok := parseHuggingFaceSlug(kind, item.identifier())
			if !ok {
				logging.OrDiscard(s.Logger).Warn("skipping Hugging Face item with unexpected identifier", "index", idx, "identifier", item.identifier())
				continue
			}
			if err := yield(huggingFaceRepo{
				Kind:       kind,
				Owner:      owner,
				Name:       name,
				Visibility: item.visibility(),
			}); err != nil {
				return err
			}
			logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "discovered Hugging Face repository", "owner", owner, "repo", name, "type", string(kind))
		}
		return nil
	})
}

func parseHuggingFaceSlug(kind RepoKind, raw string) (owner, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := ParseURL(raw)
		if err != nil || parsed.Kind != "repo" || parsed.Type != kind {
			return "", "", false
		}
		return parsed.Owner, parsed.Name, true
	}
	parts := cleanPathSegments(raw)
	if len(parts) > 0 {
		switch kind {
		case RepoKindDataset:
			if parts[0] == "datasets" || parts[0] == "dataset" {
				parts = parts[1:]
			}
		case RepoKindSpace:
			if parts[0] == "spaces" || parts[0] == "space" {
				parts = parts[1:]
			}
		case RepoKindModel:
			if parts[0] == "models" || parts[0] == "model" {
				parts = parts[1:]
			}
		}
	}
	if len(parts) < 2 {
		return "", "", false
	}
	owner = strings.TrimSpace(parts[0])
	name = strings.TrimSuffix(strings.Join(parts[1:], "/"), ".git")
	return owner, name, owner != "" && name != ""
}

func (s *Source) scanRepo(ctx context.Context, repo huggingFaceRepo, yield sources.FragmentsFunc) error {
	logger := logging.OrDiscard(s.Logger).With("repo", repo.Slug(), "type", string(repo.Kind))
	repoAttrs := s.repoAttributes(repo, "")
	if s.Prefilter != nil && s.Prefilter(s.repoAttributes(repo, ResourceRepo)) {
		logger.Debug("skipping Hugging Face repository based on prefilter")
		return nil
	}
	hfYield := s.wrapYieldWithAttrs(repoAttrs, yield)

	run := func(label string, fn func() error) error {
		logger.Info("scanning", "resource", label)
		if err := fn(); err != nil {
			logger.Error("scan failed", "error", err, "resource", label)
			return err
		}
		logger.Info("completed", "resource", label)
		return nil
	}

	if s.Resources.Has(ResourceTypeRepos) {
		if err := run(string(ResourceTypeRepos), func() error {
			return s.scanRepoGit(ctx, repo, hfYield)
		}); err != nil {
			return err
		}
	}
	if s.Resources.Has(ResourceTypeDiscussions) || s.Resources.Has(ResourceTypePRs) {
		if err := run("community", func() error { return s.scanCommunity(ctx, repo, hfYield) }); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) repoAttributes(repo huggingFaceRepo, resource string) map[string]string {
	attrs := map[string]string{
		AttrOwner:      repo.Owner,
		AttrRepo:       repo.Name,
		AttrRepoType:   string(repo.Kind),
		AttrRepoURL:    repo.WebURL(s.baseURL),
		AttrVisibility: repo.Visibility,
	}
	if resource != "" {
		attrs[sources.AttrResource] = resource
	}
	return attrs
}

func (s *Source) wrapYieldWithAttrs(attrs map[string]string, yield sources.FragmentsFunc) sources.FragmentsFunc {
	var mu sync.Mutex
	return func(fragment sources.Fragment, err error) error {
		if err == nil {
			for k, v := range attrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
			}
			if s.Prefilter != nil && s.Prefilter(fragment.Attributes) {
				return nil
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return yield(fragment, err)
	}
}

func (s *Source) scanRepoGit(ctx context.Context, repo huggingFaceRepo, yield sources.FragmentsFunc) error {
	remote := repo.GitURL(s.baseURL)
	return scm.CloneToTempDir(ctx, remote, s.Token, "betterleaks-huggingface-*", scm.CloneOptions{Mirror: true}, func(repoPath string) error {
		src := &sources.Git{
			Logger:   s.Logger,
			RepoPath: repoPath, Prefilter: s.Prefilter,
			Platform: scm.UnknownPlatform, RemoteURL: repo.WebURL(s.baseURL),
			MaxArchiveDepth: s.MaxArchiveDepth,
			LogOpts:         s.LogOpts,
		}
		return src.Fragments(ctx, yield)
	})
}

type huggingFaceBucketEntry struct {
	Type         string `json:"type"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
	XetHash      string `json:"xetHash"`
}

func (s *Source) scanBucket(ctx context.Context, bucket huggingFaceBucket, yield sources.FragmentsFunc) error {
	logger := logging.OrDiscard(s.Logger).With("bucket", bucket.ID())
	logger.Info("scanning Hugging Face bucket", "prefix", bucket.Prefix)
	if s.Prefilter != nil && s.Prefilter(s.bucketAttributes(bucket, nil, ResourceBucket)) {
		logger.Debug("skipping Hugging Face bucket based on prefilter")
		return nil
	}
	maxSize := s.MaxBucketObjectSize
	if maxSize <= 0 {
		maxSize = huggingFaceDefaultMaxBucketObjectSize
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)
	var scanned atomic.Int64
	var queued int
	var skippedOversized int
	var skippedPrefilter int
	listErr := s.streamBucketTree(gctx, bucket, func(entry huggingFaceBucketEntry) error {
		if err := gctx.Err(); err != nil {
			return err
		}
		if entry.Type != "file" || entry.Path == "" {
			return nil
		}
		if maxSize > 0 && entry.Size > maxSize {
			logging.OrDiscard(s.Logger).Debug("skipping oversized Hugging Face bucket object",
				"bucket", bucket.ID(),
				"path", entry.Path,
				"size", entry.Size,
				"max_size", maxSize,
			)
			skippedOversized++
			return nil
		}
		if s.Prefilter != nil && s.Prefilter(s.bucketAttributes(bucket, &entry, ResourceBucket)) {
			logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "skipping Hugging Face bucket object based on prefilter", "bucket", bucket.ID(), "path", entry.Path)
			skippedPrefilter++
			return nil
		}
		if entry.Size > huggingFaceLargeObjectWarnThreshold {
			logging.OrDiscard(s.Logger).Warn("downloading and scanning large Hugging Face bucket object", "bucket", bucket.ID(), "path", entry.Path, "size", entry.Size)
		}
		queued++
		logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "queueing Hugging Face bucket object scan", "bucket", bucket.ID(), "path", entry.Path, "size", entry.Size)
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			if err := s.scanBucketObject(gctx, bucket, entry, yield); err != nil {
				return err
			}
			scanned.Add(1)
			return nil
		})
		return nil
	})
	if listErr != nil {
		cancel()
	}
	if err := errors.Join(listErr, g.Wait()); err != nil {
		return err
	}
	logger.Info("completed Hugging Face bucket scan",
		"queued_objects", queued,
		"skipped_oversized", skippedOversized,
		"skipped_prefilter", skippedPrefilter,
		"scanned_objects", scanned.Load(),
	)
	return nil
}

func (s *Source) streamBucketTree(ctx context.Context, bucket huggingFaceBucket, yield func(huggingFaceBucketEntry) error) error {
	endpoint := "buckets/" + escapePathSegments(bucket.ID()) + "/tree"
	u, err := s.apiURL(endpoint)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("recursive", "true")
	if bucket.Prefix != "" {
		q.Set("prefix", bucket.Prefix)
	}
	u.RawQuery = q.Encode()

	logging.OrDiscard(s.Logger).Info("listing Hugging Face bucket tree", "bucket", bucket.ID(), "prefix", bucket.Prefix)
	return s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceBucketEntry
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode bucket tree: %w; body snippet: %s", err, snippet(body))
		}
		for _, entry := range page {
			if err := yield(entry); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Source) scanBucketObject(ctx context.Context, bucket huggingFaceBucket, entry huggingFaceBucketEntry, yield sources.FragmentsFunc) error {
	attrs := s.bucketAttributes(bucket, &entry, ResourceBucket)
	logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "downloading Hugging Face bucket object", "bucket", bucket.ID(), "path", entry.Path, "size", entry.Size)
	return download.WithFile(ctx, download.Options{
		URL:         s.bucketObjectURL(bucket, entry.Path),
		BearerToken: s.Token,
		HTTPClient:  s.httpClient,
		TempPattern: "betterleaks-huggingface-bucket-*",
		Logger:      s.Logger,
	}, func(content *os.File) error {
		file := &sources.File{
			Content: content, Path: entry.Path, Attributes: attrs,
			Logger: s.Logger, Prefilter: s.Prefilter,
			MaxArchiveDepth: max(1, s.MaxArchiveDepth), DetectArchive: true,
		}
		return file.Fragments(ctx, yield)
	})
}

func (s *Source) bucketObjectURL(bucket huggingFaceBucket, objectPath string) string {
	u := *s.baseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + "/buckets/" + escapePathSegments(bucket.ID()) + "/resolve/" + escapePathSegments(strings.TrimPrefix(objectPath, "/"))
	u.RawQuery = ""
	return u.String()
}

func (s *Source) bucketAttributes(bucket huggingFaceBucket, entry *huggingFaceBucketEntry, resource string) map[string]string {
	attrs := map[string]string{
		AttrOwner:     bucket.Owner,
		AttrBucket:    bucket.Name,
		AttrBucketURL: bucket.WebURL(s.baseURL),
	}
	if bucket.Private {
		attrs[AttrVisibility] = "private"
	}
	if resource != "" {
		attrs[sources.AttrResource] = resource
	}
	if entry != nil {
		attrs[AttrBucketPath] = entry.Path
		attrs[sources.AttrPath] = entry.Path
		attrs[sources.AttrURL] = s.bucketObjectURL(bucket, entry.Path)
		if entry.Size > 0 {
			attrs[AttrBucketSize] = strconv.FormatInt(entry.Size, 10)
		}
		if entry.LastModified != "" {
			attrs[AttrBucketMTime] = entry.LastModified
		}
		if entry.XetHash != "" {
			attrs[AttrBucketXetHash] = entry.XetHash
		}
	}
	return attrs
}

type huggingFaceDiscussion struct {
	Num           int    `json:"num"`
	Title         string `json:"title"`
	IsPullRequest bool   `json:"isPullRequest"`
	Author        any    `json:"author"`
}

type huggingFaceDiscussionDetails struct {
	Num           int                          `json:"num"`
	Title         string                       `json:"title"`
	IsPullRequest bool                         `json:"isPullRequest"`
	Author        any                          `json:"author"`
	Events        []huggingFaceDiscussionEvent `json:"events"`
}

type huggingFaceDiscussionEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	CreatedAt string `json:"createdAt"`
	Author    any    `json:"author"`
	Data      struct {
		Latest struct {
			Raw string `json:"raw"`
		} `json:"latest"`
	} `json:"data"`
}

func (s *Source) scanCommunity(ctx context.Context, repo huggingFaceRepo, yield sources.FragmentsFunc) error {
	return s.streamDiscussions(ctx, repo, func(discussion huggingFaceDiscussion) error {
		if discussion.IsPullRequest && !s.Resources.Has(ResourceTypePRs) {
			return nil
		}
		if !discussion.IsPullRequest && !s.Resources.Has(ResourceTypeDiscussions) {
			return nil
		}
		detail, err := s.getDiscussionDetails(ctx, repo, discussion.Num)
		if err != nil {
			return err
		}
		return s.emitDiscussionEvents(ctx, repo, detail, yield)
	})
}

func (s *Source) streamDiscussions(ctx context.Context, repo huggingFaceRepo, yield func(huggingFaceDiscussion) error) error {
	u, err := s.apiURL(repo.Kind.apiPath() + "/" + escapePathSegments(repo.Slug()) + "/discussions")
	if err != nil {
		return err
	}
	return s.paginateJSON(ctx, u, func(body []byte) error {
		var page struct {
			Discussions []huggingFaceDiscussion `json:"discussions"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode discussions: %w; body snippet: %s", err, snippet(body))
		}
		for _, discussion := range page.Discussions {
			if err := yield(discussion); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Source) getDiscussionDetails(ctx context.Context, repo huggingFaceRepo, num int) (huggingFaceDiscussionDetails, error) {
	u, err := s.apiURL(repo.Kind.apiPath() + "/" + escapePathSegments(repo.Slug()) + "/discussions/" + strconv.Itoa(num))
	if err != nil {
		return huggingFaceDiscussionDetails{}, err
	}
	body, err := s.get(ctx, u)
	if err != nil {
		return huggingFaceDiscussionDetails{}, err
	}
	var detail huggingFaceDiscussionDetails
	if err := json.Unmarshal(body, &detail); err != nil {
		return huggingFaceDiscussionDetails{}, fmt.Errorf("decode discussion details: %w; body snippet: %s", err, snippet(body))
	}
	return detail, nil
}

func (s *Source) emitDiscussionEvents(ctx context.Context, repo huggingFaceRepo, detail huggingFaceDiscussionDetails, yield sources.FragmentsFunc) error {
	resource := ResourceDiscussion
	if detail.IsPullRequest {
		resource = ResourcePR
	}
	for _, event := range detail.Events {
		raw := event.Data.Latest.Raw
		if raw == "" {
			continue
		}
		attrs := s.repoAttributes(repo, ResourceComment)
		attrs[AttrDiscussionNumber] = strconv.Itoa(detail.Num)
		attrs[AttrCommentID] = event.ID
		attrs[AttrAuthor] = huggingFaceAuthorName(event.Author)
		attrs[sources.AttrURL] = fmt.Sprintf("%s/discussions/%d#%s", strings.TrimRight(repo.WebURL(s.baseURL), "/"), detail.Num, event.ID)
		if event.ID == "" {
			attrs[sources.AttrURL] = fmt.Sprintf("%s/discussions/%d", strings.TrimRight(repo.WebURL(s.baseURL), "/"), detail.Num)
		}
		attrs[AttrCommunityResource] = resource
		fragment := sources.Fragment{Raw: raw, Attributes: attrs}
		if s.Prefilter != nil && s.Prefilter(fragment.Attributes) {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := yield(fragment, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func huggingFaceAuthorName(v any) string {
	switch author := v.(type) {
	case string:
		return author
	case map[string]any:
		for _, key := range []string{"name", "fullname", "username", "user"} {
			if val, ok := author[key].(string); ok {
				return val
			}
		}
	}
	return ""
}

func (k RepoKind) apiPath() string {
	switch k {
	case RepoKindDataset:
		return "datasets"
	case RepoKindSpace:
		return "spaces"
	default:
		return "models"
	}
}

func (s *Source) ensureClient() error {
	if s.restRetry == nil {
		s.restRetry = httpclient.NewRetryTransport(nil)
	}
	if s.baseURL == nil {
		u, err := url.Parse(huggingFaceDefaultBase)
		if err != nil {
			return err
		}
		s.baseURL = u
	}
	if s.httpClient == nil {
		s.httpClient = httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.baseURL.Host)
	}
	if s.apiSem == nil {
		s.apiSem = make(chan struct{}, huggingFaceAPIConcurrency)
	}
	return nil
}

func (s *Source) apiURL(endpoint string) (*url.URL, error) {
	if err := s.ensureClient(); err != nil {
		return nil, err
	}
	endpoint = strings.TrimPrefix(endpoint, "/")
	u := *s.baseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/" + endpoint
	u.RawQuery = ""
	return &u, nil
}

func (s *Source) acquireAPISlot(ctx context.Context) (func(), error) {
	if s.apiSem == nil {
		return func() {}, nil
	}
	select {
	case s.apiSem <- struct{}{}:
		return func() { <-s.apiSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Source) get(ctx context.Context, u *url.URL) ([]byte, error) {
	release, err := s.acquireAPISlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "requesting Hugging Face API resource", "url", u.String())
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("Hugging Face API request %s failed: %s: %s", u.String(), resp.Status, snippet(body))
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && s.Token == "" {
			msg += "; set HUGGINGFACE_TOKEN or pass --token for private resources"
		}
		return nil, errors.New(msg)
	}
	return body, nil
}

func (s *Source) paginateJSON(ctx context.Context, first *url.URL, consume func([]byte) error) error {
	current := first
	for {
		release, err := s.acquireAPISlot(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			release()
			return err
		}
		logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "requesting Hugging Face API page", "url", current.String())
		resp, err := s.httpClient.Do(req)
		release()
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := fmt.Sprintf("Hugging Face API request %s failed: %s: %s", current.String(), resp.Status, snippet(body))
			if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && s.Token == "" {
				msg += "; set HUGGINGFACE_TOKEN or pass --token for private resources"
			}
			return errors.New(msg)
		}
		if err := consume(body); err != nil {
			return err
		}
		next := parseLinkNext(resp.Header.Get("Link"))
		if next == "" {
			return nil
		}
		u, err := url.Parse(next)
		if err != nil {
			return fmt.Errorf("parse next link: %w", err)
		}
		if !u.IsAbs() {
			u = current.ResolveReference(u)
		}
		if u.Scheme != current.Scheme || u.Host != current.Host {
			return fmt.Errorf("refusing Hugging Face pagination link to unexpected host %q", u.String())
		}
		current = u
	}
}

func parseLinkNext(value string) string {
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		left, _, ok := strings.Cut(part, ">")
		if !ok {
			continue
		}
		return strings.TrimPrefix(strings.TrimSpace(left), "<")
	}
	return ""
}

func snippet(body []byte) string {
	text := string(body)
	if len([]rune(text)) <= huggingFaceSnippetLimit {
		return text
	}
	runes := []rune(text)
	return string(runes[:huggingFaceSnippetLimit]) + "..."
}

func (s *Source) isExcluded(fullName string) bool {
	lp := strings.ToLower(fullName)
	for _, pattern := range s.ExcludeRepos {
		if matched, _ := filepath.Match(strings.ToLower(pattern), lp); matched {
			return true
		}
	}
	return false
}

func escapePathSegments(value string) string {
	parts := cleanPathSegments(value)
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
